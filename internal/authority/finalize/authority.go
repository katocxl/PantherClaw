// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Signer signs a JOSE payload with a typed header (platform keys).
type Signer interface {
	Sign(typ string, payload []byte) (string, error)
}

// Reason codes of the final binding.
const (
	ReasonConcurrentChange = "CONCURRENT_CHANGE"
	ReasonDuplicateRequest = "DUPLICATE_REQUEST"
	maxAttempts            = 3
)

// DefaultPermitTTL is the permit lifetime (HR-009).
const DefaultPermitTTL = 5 * time.Second

// Gateway is the authenticated gateway asking. Its org comes from its
// credential, never from the request (HR-020).
type Gateway struct {
	ID  string
	Org ids.OrgID
}

// Authority decides and binds actions.
type Authority struct {
	Pipeline  *pipeline.Pipeline
	Store     Store
	Receipts  Signer
	Permits   Signer
	Issuer    string
	PermitTTL time.Duration
	Log       *slog.Logger
}

// Result is the answer to Authorize.
type Result struct {
	Decision      adomain.Decision
	TransactionID ids.UUID
	Evaluation    int
	ActionHash    string
	EffectiveHash string
	BasisDigest   string
	Reasons       []adomain.Reason
	Checklist     []pipeline.Item
	Obligations   []pdomain.Obligation
	Permit        string
	PermitID      ids.UUID
	Epoch         int64
	Receipt       string
	// Mode is the route's mode (pipeline.ModeEnforce or ModeMonitor); in
	// monitor mode the decision is hypothetical and a permit, when present,
	// is what tells the gateway to dispatch (HR-184). AccessMode is how the
	// connection's credential reaches the target, when the action names one.
	Mode       string
	AccessMode string
	// Repeat is set when the answer is a stored decision (HR-005).
	Repeat bool
}

// Authorize decides one action and binds the decision. A finalized
// (run, action) never yields a second permit: repeats return the stored
// decision (HR-005); the same ids with another action hash are denied as
// tampering (HR-006); an OPEN transaction is evaluated again, at most
// MaxEvaluations times.
func (a *Authority) Authorize(ctx context.Context, gw Gateway, req pipeline.Request) (Result, error) {
	act := req.Action.Action
	if org, err := act.OrgID(); err != nil || org != gw.Org || req.Org != gw.Org {
		a.log(ctx).WarnContext(ctx, "authz.org_mismatch", slog.String("gateway_id", gw.ID))
		// A decision, not an error: the gateway asserted another org (HR-020).
		return Result{Decision: adomain.Deny, ActionHash: req.Action.HashHex(), Reasons: []adomain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: adomain.ReasonOrgMismatch, Check: "identity", Decisive: true,
		}}}, nil
	}
	run, err1 := ids.ParseUUID(act.RunID)
	action, err2 := ids.ParseUUID(act.ActionID)
	if err1 != nil || err2 != nil {
		return Result{Decision: adomain.CannotAuthorize, ActionHash: req.Action.HashHex(), Reasons: []adomain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: adomain.ReasonAmbiguousInput, Check: "exact_meaning", Decisive: true,
		}}}, nil
	}
	for attempt := 0; ; attempt++ {
		if attempt > maxAttempts+1 {
			return Result{}, fmt.Errorf("finalize: no stable decision after %d attempts", attempt)
		}
		prev, err := a.Store.Lookup(ctx, gw.Org, run, action)
		if err != nil {
			return Result{}, fmt.Errorf("finalize: lookup: %w", err)
		}
		if prev != nil {
			if prev.ActionHash != req.Action.HashHex() {
				return a.tampered(ctx, gw, req, *prev)
			}
			if prev.Final || prev.Evaluations >= MaxEvaluations {
				return repeat(*prev, req.Action.HashHex()), nil
			}
		}
		req.Gateway = gw.ID // the certificate's gateway, never the request's
		ev, err := a.Pipeline.Evaluate(ctx, req)
		if err != nil {
			return Result{}, err
		}
		if attempt >= maxAttempts {
			ev = override(ev, ReasonConcurrentChange, "the authority changed while deciding; try again")
		}
		res, err := a.bind(ctx, gw, ev, prev)
		switch {
		case err == nil:
			a.log(ctx).InfoContext(ctx, "authz.decision", slog.String("txn_id", res.TransactionID.String()),
				slog.String("decision", string(res.Decision)), slog.String("reason_code", ev.Decisive().Code))
			return res, nil
		case errors.Is(err, ErrParked):
			ev = override(ev, pipeline.ReasonReconciliation, "an identical irreversible action is in flight, unknown or recently succeeded")
			if res, err = a.bind(ctx, gw, ev, prev); err == nil {
				return res, nil
			}
			if !retryable(err) {
				return Result{}, err
			}
		case retryable(err):
		default:
			return Result{}, err
		}
	}
}

func retryable(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, ErrExhausted) || errors.Is(err, ErrDuplicate) || errors.Is(err, ErrParked)
}

// override records ev as CANNOT_AUTHORIZE for a final-binding reason,
// without reservations: an OPEN transaction the agent may resubmit.
func override(ev *pipeline.Evaluation, code, detail string) *pipeline.Evaluation {
	out := *ev
	out.Decision = adomain.CannotAuthorize
	out.Checklist = append([]pipeline.Item{{
		Step: pipeline.StepFinalBinding, Check: "final_binding", Status: pipeline.StatusMissing,
		Code: code, Detail: detail, Decisive: true,
	}}, undecided(ev.Checklist)...)
	out.Plan.Budgets, out.Plan.Counters = nil, nil
	return &out
}

func undecided(items []pipeline.Item) []pipeline.Item {
	out := make([]pipeline.Item, len(items))
	for i, it := range items {
		it.Decisive = false
		out[i] = it
	}
	return out
}

// monitorView is what a monitor-mode evaluation binds (HR-184): the
// hypothetical decision and its explanation, but no reservation, so
// nothing is reserved, counted or claimed.
func monitorView(ev *pipeline.Evaluation) *pipeline.Evaluation {
	out := *ev
	out.Plan = gdomain.Plan{}
	return &out
}

// bind writes one evaluation. A monitor-mode evaluation whose identity and
// containment passed gets a permit whatever its (hypothetical) decision,
// with nothing reserved, and closes its transaction so no second permit
// can follow (HR-184).
func (a *Authority) bind(ctx context.Context, gw Gateway, ev *pipeline.Evaluation, prev *Stored) (Result, error) {
	monitor := ev.MonitorPermit()
	if monitor {
		ev = monitorView(ev)
	}
	w := Write{
		Eval: ev, Prev: prev, Final: Final(ev.Decision) || monitor, Reason: ev.Decisive().Code, GatewayID: gw.ID,
		TransactionID: ids.NewV7(), Evaluation: 1,
	}
	if prev != nil {
		w.TransactionID, w.Evaluation = prev.TransactionID, prev.Evaluations+1
	}
	res := Result{
		Decision: ev.Decision, TransactionID: w.TransactionID, Evaluation: w.Evaluation, ActionHash: ev.ActionHash,
		EffectiveHash: ev.EffectiveHash, BasisDigest: ev.Basis.Digest(), Checklist: ev.Checklist,
		Obligations: ev.Obligations, Reasons: reasons(ev.Checklist), Mode: ev.Mode,
	}
	if ev.Connection != nil {
		res.AccessMode = ev.Connection.AccessMode
	}
	if monitor {
		p, err := a.permit(gw, ev, w.TransactionID)
		if err != nil {
			return Result{}, err
		}
		w.Permit = p
		res.Permit, res.PermitID, res.Epoch = p.JWS, p.ID, p.Epoch
	} else if ev.Permits() {
		rows, err := a.Store.Prepare(ctx, gw.Org, ev.Plan)
		if err != nil {
			return Result{}, err
		}
		w.Rows, w.Lines = rows, lines(ev, rows)
		if ev.DedupeKey != "" {
			w.Claim = &ClaimWrite{Key: ev.DedupeKey, TransactionID: w.TransactionID}
		}
		p, err := a.permit(gw, ev, w.TransactionID)
		if err != nil {
			return Result{}, err
		}
		w.Permit = p
		res.Permit, res.PermitID, res.Epoch = p.JWS, p.ID, p.Epoch
	}
	w.Sign = func(budgets []BudgetState) (Receipt, error) {
		return a.receipt(gw, ev, w.TransactionID, w.Evaluation, budgets)
	}
	if err := a.Store.Finalize(ctx, gw.Org, w); err != nil {
		return Result{}, err
	}
	stored, err := a.Store.Lookup(ctx, gw.Org, ev.RunID, ev.ActionID)
	if err == nil && stored != nil {
		res.Receipt = stored.Receipt
	}
	return res, nil
}

// lines turns a plan into reservation lines on resolved rows.
func lines(ev *pipeline.Evaluation, rows []Row) []bdomain.Line {
	byRef := map[bdomain.Ref]Row{}
	for _, r := range rows {
		byRef[r.Ref] = r
	}
	var out []bdomain.Line
	for _, d := range ev.Plan.Budgets {
		r := byRef[d.Ref]
		out = append(out, bdomain.Line{Kind: bdomain.KindBudget, ID: r.ID, Rank: d.Ref.Owner.Rank, Amount: d.Amount})
	}
	for _, d := range ev.Plan.Counters {
		r := byRef[d.Ref]
		out = append(out, bdomain.Line{Kind: bdomain.KindCounter, ID: r.ID, Rank: d.Ref.Owner.Rank})
	}
	return bdomain.Order(out)
}

// reasons lists the decisive item and every blocking item (PAP-1 §7.1).
func reasons(items []pipeline.Item) []adomain.Reason {
	var out []adomain.Reason
	for _, it := range items {
		if it.Decisive || (it.Status != pipeline.StatusPassed && it.Status != pipeline.StatusNotApplicable &&
			it.Status != pipeline.StatusNotEvaluated && it.Status != pipeline.StatusAnnotated) {
			out = append(out, adomain.Reason{Code: it.Code, Check: it.Check, Detail: it.Detail, Decisive: it.Decisive})
		}
	}
	return out
}

func repeat(s Stored, hash string) Result {
	return Result{
		Decision: s.Decision, TransactionID: s.TransactionID, Evaluation: s.Evaluations, ActionHash: hash, EffectiveHash: hash,
		Receipt: s.Receipt, Repeat: true, Reasons: []adomain.Reason{
			{Code: s.Reason, Check: "stored", Decisive: true},
			{Code: ReasonDuplicateRequest, Check: "idempotency"},
		},
	}
}

// tampered answers a request whose action hash differs from the stored one
// for the same (run, action): DENY ACTION_TAMPERED and a security event
// (HR-006). An OPEN transaction is closed with that denial so the original
// action cannot be resumed.
func (a *Authority) tampered(ctx context.Context, gw Gateway, req pipeline.Request, prev Stored) (Result, error) {
	a.log(ctx).WarnContext(ctx, "security.action_tampered", slog.String("txn_id", prev.TransactionID.String()), slog.String("gateway_id", gw.ID))
	res := Result{
		Decision: adomain.Deny, TransactionID: prev.TransactionID, ActionHash: req.Action.HashHex(), EffectiveHash: req.Action.HashHex(),
		Reasons: []adomain.Reason{{
			Code: adomain.ReasonActionTampered, Check: "identity", Decisive: true,
			Detail: "this run and action id were already used for another action",
		}},
	}
	var receipt *Receipt
	if !prev.Final {
		ev := &pipeline.Evaluation{
			Decision: adomain.Deny, Org: gw.Org, ActionHash: req.Action.HashHex(), EffectiveHash: req.Action.HashHex(),
			Checklist: []pipeline.Item{{
				Step: pipeline.StepFinalBinding, Check: "final_binding", Status: pipeline.StatusFailed,
				Code: adomain.ReasonActionTampered, Detail: res.Reasons[0].Detail, Decisive: true,
			}},
		}
		ev.RunID, _ = ids.ParseUUID(req.Action.Action.RunID)
		ev.ActionID, _ = ids.ParseUUID(req.Action.Action.ActionID)
		r, err := a.receipt(gw, ev, prev.TransactionID, prev.Evaluations+1, nil)
		if err != nil {
			return Result{}, err
		}
		receipt, res.Receipt, res.Evaluation = &r, r.JWS, prev.Evaluations+1
	}
	if err := a.Store.Tamper(ctx, gw.Org, prev, receipt, gw.ID); err != nil && !errors.Is(err, ErrConflict) {
		return Result{}, err
	}
	return res, nil
}

// BeginDispatch is the commit point before the gateway sends anything
// (HR-001). Any error means: do not dispatch.
func (a *Authority) BeginDispatch(ctx context.Context, gw Gateway, permit ids.UUID, epoch int64) error {
	return a.Store.BeginDispatch(ctx, gw.Org, gw.ID, permit, epoch)
}

// RecordExecution settles a dispatched permit (step 10) and returns the
// signed execution receipt.
func (a *Authority) RecordExecution(ctx context.Context, gw Gateway, e Execution) (string, error) {
	if e.Outcome != Accepted && e.Outcome != Failed && e.Outcome != Unknown {
		return "", ErrOutcomeInvalid
	}
	return a.Store.RecordExecution(ctx, gw.Org, gw.ID, e, func(txn ids.UUID, now time.Time) (Receipt, error) {
		return a.executionReceipt(gw, e, txn, now)
	})
}

// ErrOutcomeInvalid refuses an outcome other than accepted, failed or
// unknown.
var ErrOutcomeInvalid = pcerr.New(pcerr.InvalidArgument, "OUTCOME_INVALID", "unknown outcome")

func (a *Authority) log(context.Context) *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

func (a *Authority) ttl() time.Duration {
	if a.PermitTTL <= 0 {
		return DefaultPermitTTL
	}
	return a.PermitTTL
}
