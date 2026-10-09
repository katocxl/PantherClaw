// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package authority is the Transaction Authority of the M1.5 walking
// skeleton (ARCHITECTURE §6, ADR-0014): it decides on canonical actions,
// finalizes allowed ones in one transaction (idempotency, containment epoch,
// budget reservation, single-use permit, decision receipt), owns the
// BeginDispatch commit point and records execution outcomes. Since M3 an
// action is first tied to the verified workload that sent it and to a run
// that workload may use (HR-021, HR-022).
package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// JOSE types of Authority-signed artifacts (PAP-1 §7.2, §9).
const (
	TypePermit           = "pap-permit+jwt"
	TypeDecisionReceipt  = "pap-decision+jwt"
	TypeExecutionReceipt = "pap-execution+jwt"
	DefaultPermitTTL     = 5 * time.Second
	DefaultStaleDispatch = 30 * time.Second
	receiptKindDecision  = "receipt.decision"
	receiptKindExecution = "receipt.execution"
)

// Gateway is the authenticated gateway calling the Authority. Its org comes
// from the gateway's credential, never from the request (HR-020).
type Gateway struct {
	ID  string
	Org ids.OrgID
}

// Service is the Transaction Authority.
type Service struct {
	pool   *db.Pool
	reg    *keys.Registry
	grant  domain.DevGrant
	issuer string
	ttl    time.Duration
	log    *slog.Logger

	workloads Workloads
	runs      Runs
	legacyDev bool
}

// Config configures the Service.
type Config struct {
	Grant     domain.DevGrant
	Issuer    string
	PermitTTL time.Duration
	Logger    *slog.Logger
	// LegacyDevWorkloads accepts actions without PAP/1 credentials, as in
	// M1.5, for the development gateway until it forwards them (M3 slice
	// 13 removes it). Never in production.
	LegacyDevWorkloads bool
}

// New returns a Service.
func New(pool *db.Pool, reg *keys.Registry, cfg Config) *Service {
	ttl := cfg.PermitTTL
	if ttl <= 0 {
		ttl = DefaultPermitTTL
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "pantherclaw"
	}
	return &Service{pool: pool, reg: reg, grant: cfg.Grant, issuer: issuer, ttl: ttl, log: cfg.Logger, legacyDev: cfg.LegacyDevWorkloads}
}

// Result is the answer to Authorize.
type Result struct {
	Decision      domain.Decision
	Reasons       []domain.Reason
	TransactionID ids.UUID
	ActionHash    string
	Permit        string // JWS; only for a fresh ALLOW
	PermitID      ids.UUID
	Epoch         int64
	Receipt       string // decision receipt JWS
	// Nonce is the org's current PAP/1 nonce, for the PAP-Nonce header.
	Nonce string
}

// Authorize decides on raw canonical ActionIR bytes sent with the
// workload's PAP/1 credentials (nil only on the legacy development path).
func (s *Service) Authorize(ctx context.Context, gw Gateway, raw []byte, creds *Credentials) (Result, error) {
	p, perr := actionir.Parse(raw)
	if perr != nil {
		// Unparseable input cannot be bound to an org or action id: the answer
		// is the decision CANNOT_AUTHORIZE (not an RPC error), and no
		// transaction is recorded.
		return Result{Decision: domain.CannotAuthorize, Reasons: []domain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: domain.ReasonAmbiguousInput, Check: "exact_meaning", Decisive: true,
		}}}, nil
	}
	if org, oerr := p.Action.OrgID(); oerr != nil || org != gw.Org {
		s.log.WarnContext(ctx, "authz.org_mismatch", slog.String("gateway_id", gw.ID))
		// A decision, not an error: the gateway asserted another org (HR-020).
		return Result{Decision: domain.Deny, ActionHash: p.HashHex(), Reasons: []domain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: domain.ReasonOrgMismatch, Check: "identity", Decisive: true,
		}}}, nil
	}
	o, ok, err := s.identify(ctx, gw, p, creds)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		s.log.InfoContext(ctx, "authz.decision", slog.String("decision", string(o.Decision)), slog.String("reason_code", o.Decisive()))
		return Result{Decision: o.Decision, ActionHash: p.HashHex(), Reasons: o.Reasons, Nonce: s.nonce(ctx, gw)}, nil
	}
	run, _ := ids.ParseUUID(p.Action.RunID)
	act, _ := ids.ParseUUID(p.Action.ActionID)
	outcome := s.grant.Evaluate(p)

	res, err := s.finalize(ctx, gw, p, run, act, outcome)
	if errors.Is(err, errBudgetLost) {
		// The reservation failed after everything else was prepared: the
		// whole finalization rolled back, and the denial is recorded now.
		denied := domain.Outcome{Decision: domain.Deny, Reasons: []domain.Reason{{
			Code: domain.ReasonBudgetExhausted, Check: "boundaries", Decisive: true,
		}}}
		res, err = s.finalize(ctx, gw, p, run, act, denied)
	}
	if err != nil {
		return Result{}, err
	}
	s.log.InfoContext(ctx, "authz.decision", slog.String("txn_id", res.TransactionID.String()),
		slog.String("decision", string(res.Decision)), slog.String("reason_code", decisive(res.Reasons)))
	res.Nonce = s.nonce(ctx, gw)
	return res, nil
}

var errBudgetLost = errors.New("authority: budget reservation lost")

func decisive(rs []domain.Reason) string {
	return domain.Outcome{Reasons: rs}.Decisive()
}

// finalize records the decision in one transaction. For ALLOW it also
// reserves budget (last, to hold the hot row briefly), issues the permit and
// writes the decision receipt. A lost reservation returns errBudgetLost after
// rolling everything back.
func (s *Service) finalize(ctx context.Context, gw Gateway, p actionir.Parsed, run, act ids.UUID, o domain.Outcome) (Result, error) {
	var res Result
	err := s.pool.InTenantTx(ctx, gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		res = Result{ActionHash: p.HashHex()}

		// Idempotency: (org, run, action) is decided once (HR-005, HR-006).
		prev, err := q.GetTransactionByAction(ctx, gw.Org, run, act)
		switch {
		case err == nil:
			res.TransactionID = prev.ID
			if hex.EncodeToString(prev.ActionHash) != p.HashHex() {
				s.log.WarnContext(ctx, "security.action_tampered", slog.String("txn_id", prev.ID.String()),
					slog.String("gateway_id", gw.ID))
				res.Decision = domain.Deny
				res.Reasons = []domain.Reason{{Code: domain.ReasonActionTampered, Check: "identity", Decisive: true}}
				return nil
			}
			res.Decision = domain.Decision(prev.Decision)
			res.Reasons = []domain.Reason{
				{Code: prev.ReasonCode, Check: "stored", Decisive: true},
				{Code: domain.ReasonDuplicateRequest, Check: "idempotency"},
			}
			res.Receipt, _ = q.GetDecisionReceipt(ctx, gw.Org, prev.ID)
			return nil // never a second permit
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}

		cont, err := q.ShareContainment(ctx, gw.Org)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			o = domain.Outcome{Decision: domain.CannotAuthorize, Reasons: []domain.Reason{{
				Code: domain.ReasonContainmentUnknown, Check: "containment", Decisive: true,
			}}}
		case err != nil:
			return err
		case cont.KillSwitch:
			o = domain.Outcome{Decision: domain.Deny, Reasons: []domain.Reason{{
				Code: domain.ReasonKillSwitch, Check: "containment", Decisive: true,
			}}}
		}

		var budget dbq.GetBudgetByNameRow
		if o.Decision.Permits() {
			budget, err = q.GetBudgetByName(ctx, gw.Org, s.grant.BudgetName)
			if errors.Is(err, pgx.ErrNoRows) {
				o = domain.Outcome{Decision: domain.CannotAuthorize, Reasons: []domain.Reason{{
					Code: domain.ReasonBudgetUnavailable, Check: "boundaries", Decisive: true,
				}}}
			} else if err != nil {
				return err
			}
		}

		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		txnID := ids.NewV7()
		res.TransactionID, res.Decision, res.Reasons = txnID, o.Decision, o.Reasons
		params := dbq.InsertTransactionParams{
			OrgID: gw.Org, ID: txnID, RunID: run, ActionID: act, ActionHash: p.Hash[:],
			Operation: p.Action.Operation, Decision: string(o.Decision), ReasonCode: o.Decisive(), GatewayID: gw.ID,
		}
		if o.Decision.Permits() {
			cur := string(o.Amount.Currency)
			params.BudgetID, params.Amount, params.Currency = &budget.ID, &o.Amount.Amount, &cur
		}
		if err := q.InsertTransaction(ctx, params); err != nil {
			return err
		}

		if o.Decision.Permits() {
			permitID := ids.NewV7()
			exp := now.Add(s.ttl)
			if err := q.InsertPermit(ctx, dbq.InsertPermitParams{
				OrgID: gw.Org, ID: permitID, TransactionID: txnID, GatewayID: gw.ID, Epoch: cont.Epoch,
				BudgetID: budget.ID, Amount: o.Amount.Amount, ExpiresAt: exp,
			}); err != nil {
				return err
			}
			permit, err := s.signPermit(gw, txnID, permitID, p.HashHex(), cont.Epoch, now, exp)
			if err != nil {
				return err
			}
			res.Permit, res.PermitID, res.Epoch = permit, permitID, cont.Epoch
		}

		receipt, err := s.writeDecisionReceipt(ctx, tx, gw, p, txnID, o, now)
		if err != nil {
			return err
		}
		res.Receipt = receipt

		if o.Decision.Permits() {
			if err := q.InsertBudgetLedger(ctx, dbq.InsertBudgetLedgerParams{
				OrgID: gw.Org, ID: ids.NewV7(), BudgetID: budget.ID, TransactionID: txnID, Kind: "reserve", Amount: o.Amount.Amount,
			}); err != nil {
				return err
			}
			// Budget last: the reservation is the final statement, so the hot
			// row is locked only until COMMIT (ARCHITECTURE §6.3).
			if err := db.ExpectOneRow(q.ReserveBudget(ctx, dbq.ReserveBudgetParams{
				Amount: o.Amount.Amount, OrgID: gw.Org, ID: budget.ID, Currency: string(o.Amount.Currency),
			})); errors.Is(err, db.ErrLostRace) {
				return errBudgetLost
			} else if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errBudgetLost) {
			return Result{}, err
		}
		if db.IsUniqueViolation(err) {
			// A concurrent request for the same (org, run, action) won;
			// answer with its stored decision.
			return s.finalize(ctx, gw, p, run, act, o)
		}
		return Result{}, fmt.Errorf("authority: finalize: %w", err)
	}
	return res, nil
}

type permitClaims struct {
	Iss string    `json:"iss"`
	Aud string    `json:"aud"`
	Jti string    `json:"jti"`
	Iat int64     `json:"iat"`
	Exp int64     `json:"exp"`
	Pap permitPAP `json:"pap"`
}

type permitPAP struct {
	V     int    `json:"v"`
	Org   string `json:"org"`
	Txn   string `json:"txn"`
	Act   string `json:"act"`
	Epoch int64  `json:"epoch"`
}

func (s *Service) signPermit(gw Gateway, txn, permit ids.UUID, act string, epoch int64, now, exp time.Time) (string, error) {
	signer, err := s.reg.Signer(keys.PurposePermits)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(permitClaims{
		Iss: s.issuer, Aud: "gw:" + gw.ID, Jti: permit.String(), Iat: now.Unix(), Exp: exp.Unix(),
		Pap: permitPAP{V: 1, Org: gw.Org.String(), Txn: txn.String(), Act: act, Epoch: epoch},
	})
	if err != nil {
		return "", err
	}
	return signer.Sign(TypePermit, b)
}

type amountJSON struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

func (s *Service) writeDecisionReceipt(ctx context.Context, tx db.TenantTx, gw Gateway, p actionir.Parsed, txn ids.UUID, o domain.Outcome, now time.Time) (string, error) {
	signer, err := s.reg.Signer(keys.PurposeReceipts)
	if err != nil {
		return "", err
	}
	var amount *amountJSON
	if o.Decision.Permits() {
		amount = &amountJSON{Value: o.Amount.Amount.String(), Currency: string(o.Amount.Currency)}
	}
	payload, err := json.Marshal(decisionReceipt{Iss: s.issuer, Jti: txn.String(), Iat: now.Unix(), Pap: decisionPAP{
		V: 1, Kind: "decision", Org: gw.Org.String(), Txn: txn.String(), Run: p.Action.RunID, Action: p.Action.ActionID,
		Act: p.HashHex(), Decision: o.Decision, Reasons: o.Reasons, Grant: s.grant.Name, Amount: amount, Gateway: gw.ID,
	}})
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(TypeDecisionReceipt, payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(jws))
	body, err := evdomain.CanonicalBody(map[string]string{
		"txn": txn.String(), "decision": string(o.Decision), "act": p.HashHex(),
		"reason": o.Decisive(), "receipt_sha256": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", err
	}
	entry, err := ledger.Append(ctx, tx, receiptKindDecision, evdomain.Actor{Type: "gateway", ID: gw.ID}, body)
	if err != nil {
		return "", err
	}
	if err := dbq.New(tx).InsertDecisionReceipt(ctx, dbq.InsertDecisionReceiptParams{
		OrgID: gw.Org, TransactionID: txn, ReceiptJws: jws, LedgerEntryID: entry.ID,
	}); err != nil {
		return "", err
	}
	return jws, nil
}

// Dispatch errors (the gateway must not dispatch on any of them).
var (
	ErrPermitUnknown  = pcerr.New(pcerr.FailedPrecondition, "PERMIT_UNKNOWN", "permit not found")
	ErrPermitUsed     = pcerr.New(pcerr.FailedPrecondition, "PERMIT_ALREADY_USED", "permit already used")
	ErrPermitExpired  = pcerr.New(pcerr.FailedPrecondition, "PERMIT_EXPIRED", "permit expired")
	ErrEpochStale     = pcerr.New(pcerr.FailedPrecondition, "EPOCH_STALE", "containment changed since the permit was issued")
	ErrKillSwitch     = pcerr.New(pcerr.Deny, "KILL_SWITCH_ENGAGED", "kill switch engaged")
	ErrNotDispatching = pcerr.New(pcerr.FailedPrecondition, "PERMIT_NOT_DISPATCHING", "permit is not dispatching")
)

// BeginDispatch is the commit point (HR-001). It returns nil only if the
// permit moved ISSUED → DISPATCHING; any error means "do not dispatch".
func (s *Service) BeginDispatch(ctx context.Context, gw Gateway, permit ids.UUID, epoch int64) error {
	return s.pool.InTenantTx(ctx, gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, err := q.BeginDispatch(ctx, dbq.BeginDispatchParams{OrgID: gw.Org, ID: permit, GatewayID: gw.ID, Epoch: epoch})
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		st, err := q.GetPermit(ctx, gw.Org, permit)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrPermitUnknown
		case err != nil:
			return err
		case st.GatewayID != gw.ID:
			return ErrPermitUnknown // another gateway's permit is not ours to use
		case st.State != "ISSUED":
			return ErrPermitUsed
		case st.KillSwitch:
			return ErrKillSwitch
		case st.Expired:
			return ErrPermitExpired
		default:
			return ErrEpochStale
		}
	})
}

// Outcome of a dispatch.
type Outcome string

// Dispatch outcomes (PAP-1 §7.4).
const (
	Accepted Outcome = "accepted"
	Failed   Outcome = "failed"
	Unknown  Outcome = "unknown"
)

// Execution describes one dispatch attempt.
type Execution struct {
	Permit         ids.UUID
	Outcome        Outcome
	TargetStatus   int32
	ResponseDigest []byte
	DispatchMS     int32
}

// RecordExecution records the outcome of a DISPATCHING permit: accepted
// commits the reservation, failed releases it, unknown keeps it held and
// leaves the permit UNKNOWN for reconciliation (HR-003).
func (s *Service) RecordExecution(ctx context.Context, gw Gateway, e Execution) (string, error) {
	var receipt string
	err := s.pool.InTenantTx(ctx, gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		to := "DISPATCHED"
		if e.Outcome == Unknown {
			to = "UNKNOWN"
		} else if e.Outcome != Accepted && e.Outcome != Failed {
			return pcerr.New(pcerr.InvalidArgument, "OUTCOME_INVALID", "unknown outcome")
		}
		row, err := q.FinishPermit(ctx, dbq.FinishPermitParams{ToState: to, OrgID: gw.Org, ID: e.Permit, GatewayID: gw.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotDispatching
		} else if err != nil {
			return err
		}
		attempt := dbq.InsertExecutionAttemptParams{
			OrgID: gw.Org, ID: ids.NewV7(), PermitID: e.Permit, TransactionID: row.TransactionID, Outcome: string(e.Outcome),
		}
		if e.TargetStatus > 0 {
			attempt.TargetStatus = &e.TargetStatus
		}
		if len(e.ResponseDigest) == sha256.Size {
			attempt.ResponseDigest = e.ResponseDigest
		}
		if e.DispatchMS >= 0 {
			attempt.DispatchMs = &e.DispatchMS
		}
		if err := q.InsertExecutionAttempt(ctx, attempt); err != nil {
			return err
		}
		kind := "hold_unknown"
		switch e.Outcome {
		case Accepted:
			kind = "commit"
		case Failed:
			kind = "release"
		case Unknown:
		}
		if err := q.InsertBudgetLedger(ctx, dbq.InsertBudgetLedgerParams{
			OrgID: gw.Org, ID: ids.NewV7(), BudgetID: row.BudgetID, TransactionID: row.TransactionID, Kind: kind, Amount: row.Amount,
		}); err != nil {
			return err
		}
		if receipt, err = s.writeExecutionReceipt(ctx, tx, gw, row.TransactionID, e); err != nil {
			return err
		}
		// Budget last, as in Authorize: the hot row is locked only until COMMIT.
		switch e.Outcome {
		case Accepted:
			err = db.ExpectOneRow(q.CommitReservation(ctx, row.Amount, gw.Org, row.BudgetID))
		case Failed:
			err = db.ExpectOneRow(q.ReleaseReservation(ctx, row.Amount, gw.Org, row.BudgetID))
		case Unknown:
		}
		if err != nil {
			return fmt.Errorf("authority: budget %s: %w", kind, err)
		}
		return nil
	})
	return receipt, err
}

func (s *Service) writeExecutionReceipt(ctx context.Context, tx db.TenantTx, gw Gateway, txn ids.UUID, e Execution) (string, error) {
	signer, err := s.reg.Signer(keys.PurposeReceipts)
	if err != nil {
		return "", err
	}
	now, err := dbq.New(tx).DBNow(ctx)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": s.issuer, "jti": e.Permit.String(), "iat": now.Unix(),
		"pap": map[string]any{
			"v": 1, "kind": "execution", "org": gw.Org.String(), "txn": txn.String(), "permit": e.Permit.String(),
			"outcome": string(e.Outcome), "target_status": e.TargetStatus, "response_digest": hex.EncodeToString(e.ResponseDigest),
			"gateway": gw.ID, "access_mode": "pantherclaw-held", "simulated": false,
		},
	})
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(TypeExecutionReceipt, payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(jws))
	body, err := evdomain.CanonicalBody(map[string]string{
		"txn": txn.String(), "permit": e.Permit.String(), "outcome": string(e.Outcome),
		"receipt_sha256": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", err
	}
	if _, err := ledger.Append(ctx, tx, receiptKindExecution, evdomain.Actor{Type: "gateway", ID: gw.ID}, body); err != nil {
		return "", err
	}
	return jws, nil
}

// SweepResult counts what one sweep changed.
type SweepResult struct {
	Released int // expired ISSUED permits whose reservation was released
	Unknown  int // stale DISPATCHING permits moved to UNKNOWN (reservation kept)
}

// SweepOrg releases expired ISSUED permits and marks stale DISPATCHING ones
// UNKNOWN, never releasing them (HR-003).
func (s *Service) SweepOrg(ctx context.Context, org ids.OrgID, staleAfter time.Duration) (SweepResult, error) {
	var r SweepResult
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		released, err := q.ReleaseExpiredPermits(ctx, org)
		if err != nil {
			return err
		}
		type sum struct {
			amount money.Decimal
			count  int32
		}
		perBudget := map[ids.UUID]sum{}
		for _, p := range released {
			if err := q.InsertBudgetLedger(ctx, dbq.InsertBudgetLedgerParams{
				OrgID: org, ID: ids.NewV7(), BudgetID: p.BudgetID, TransactionID: p.TransactionID, Kind: "release", Amount: p.Amount,
			}); err != nil {
				return err
			}
			s := perBudget[p.BudgetID]
			if s.amount, err = s.amount.Add(p.Amount); err != nil {
				return err
			}
			s.count++
			perBudget[p.BudgetID] = s
		}
		unknown, err := q.MarkStaleDispatchingUnknown(ctx, org, staleAfter.Seconds())
		if err != nil {
			return err
		}
		for _, p := range unknown {
			if err := q.InsertBudgetLedger(ctx, dbq.InsertBudgetLedgerParams{
				OrgID: org, ID: ids.NewV7(), BudgetID: p.BudgetID, TransactionID: p.TransactionID, Kind: "hold_unknown", Amount: p.Amount,
			}); err != nil {
				return err
			}
		}
		// Budget last: one release per budget, so the hot rows are locked
		// once and only until COMMIT, however many permits expired.
		for budget, s := range perBudget {
			if err := db.ExpectOneRow(q.ReleaseReservations(ctx, dbq.ReleaseReservationsParams{
				Amount: s.amount, Count: s.count, OrgID: org, ID: budget,
			})); err != nil {
				return fmt.Errorf("authority: sweep release: %w", err)
			}
		}
		r = SweepResult{Released: len(released), Unknown: len(unknown)}
		return nil
	})
	if r.Unknown > 0 {
		s.log.WarnContext(ctx, "authz.dispatch_unknown", slog.String("org_id", org.String()), slog.Int("count", r.Unknown))
	}
	return r, err
}

type decisionReceipt struct {
	Iss string      `json:"iss"`
	Jti string      `json:"jti"`
	Iat int64       `json:"iat"`
	Pap decisionPAP `json:"pap"`
}

type decisionPAP struct {
	V         int             `json:"v"`
	Kind      string          `json:"kind"`
	Org       string          `json:"org"`
	Txn       string          `json:"txn"`
	Run       string          `json:"run"`
	Action    string          `json:"action"`
	Act       string          `json:"act"`
	Decision  domain.Decision `json:"decision"`
	Reasons   []domain.Reason `json:"reasons"`
	Grant     string          `json:"grant"`
	Amount    *amountJSON     `json:"amount,omitempty"`
	Gateway   string          `json:"gateway"`
	Simulated bool            `json:"simulated"`
}

// Workloads identifies the workload behind forwarded PAP/1 credentials and
// serves nonces (identity app).
type Workloads interface {
	Identify(ctx context.Context, org ids.OrgID, in iapp.IdentifyInput) (iapp.Identified, error)
	NonceExpiry(ctx context.Context, org ids.OrgID) (string, time.Time, error)
	Discover(ctx context.Context, org ids.OrgID, in iapp.DiscoverInput) (ids.UUID, error)
}

// Runs checks and binds runs (runs app).
type Runs interface {
	Bind(ctx context.Context, org ids.OrgID, run, agent, instance ids.UUID) error
}

// WithWorkloads sets the workload identity and run checks (M3) and returns
// s.
func (s *Service) WithWorkloads(w Workloads, r Runs) *Service {
	s.workloads, s.runs = w, r
	return s
}

// Credentials are a workload request's PAP/1 credentials as the gateway
// received them (WorkloadCredentials, PAP-1 §4).
type Credentials struct {
	Token      string
	Proof      string
	BodySHA256 [sha256.Size]byte
	Method     string
	URL        string
	// ClientAddress is UNTRUSTED (HR-092 network alert only).
	ClientAddress string
}

func identityOutcome(d domain.Decision, code, detail string) domain.Outcome {
	return domain.Outcome{Decision: d, Reasons: []domain.Reason{{Code: code, Check: "identity", Detail: detail, Decisive: true}}}
}

// identify checks the workload behind an action before anything is decided
// or recorded (PAP-1 §7.1; HR-021, HR-022): an unverifiable workload is
// CANNOT_AUTHORIZE, a suspended or retired agent, an action naming another
// instance or environment, and a run it may not use are DENY. None of them
// is finalized, so a workload can never spend the (run, action) key of
// another. ok reports that the action may proceed to the grant.
func (s *Service) identify(ctx context.Context, gw Gateway, p actionir.Parsed, c *Credentials) (domain.Outcome, bool, error) {
	if c == nil {
		if s.legacyDev {
			return domain.Outcome{}, true, nil
		}
		return identityOutcome(domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(pap.CodeInvalidToken)), false, nil
	}
	if s.workloads == nil || s.runs == nil {
		return domain.Outcome{}, false, errors.New("authority: workload identity is not configured")
	}
	id, err := s.workloads.Identify(ctx, gw.Org, iapp.IdentifyInput{
		Request: pap.Request{Method: c.Method, URL: c.URL, BodySHA256: c.BodySHA256, Token: c.Token},
		Proof:   c.Proof, ClientAddress: c.ClientAddress,
	})
	var pe *pap.Error
	switch {
	case errors.As(err, &pe):
		return identityOutcome(domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(pe.Code)), false, nil
	case err != nil:
		return domain.Outcome{}, false, err
	}
	if !adomain.State(id.AgentState).Usable() {
		return identityOutcome(domain.Deny, domain.ReasonAgentUnusable, "the agent is suspended or retired"), false, nil
	}
	if p.Action.AgentInstance != id.Instance.Instance.String() || p.Action.Env != id.Environment.String() {
		s.log.WarnContext(ctx, "security.identity_mismatch", slog.String("gateway_id", gw.ID),
			slog.String("instance_id", id.Instance.Instance.String()))
		return identityOutcome(domain.Deny, domain.ReasonIdentityMismatch, "the action names another instance or environment"), false, nil
	}
	run, _ := ids.ParseUUID(p.Action.RunID)
	if err := s.runs.Bind(ctx, gw.Org, run, id.Instance.Agent, id.Instance.Instance); errors.As(err, &pe) {
		s.log.WarnContext(ctx, "security.run_mismatch", slog.String("gateway_id", gw.ID),
			slog.String("instance_id", id.Instance.Instance.String()), slog.String("run_id", run.String()))
		return identityOutcome(domain.Deny, domain.ReasonRunMismatch, string(pe.Code)), false, nil
	} else if err != nil {
		return domain.Outcome{}, false, err
	}
	return domain.Outcome{}, true, nil
}

// Nonce returns the org's current PAP/1 nonce and its expiry, or "" when
// workload identity is not configured.
func (s *Service) Nonce(ctx context.Context, gw Gateway) (string, time.Time, error) {
	if s.workloads == nil {
		return "", time.Time{}, nil
	}
	return s.workloads.NonceExpiry(ctx, gw.Org)
}

// nonce is Nonce for a response: a failure only leaves the header out.
func (s *Service) nonce(ctx context.Context, gw Gateway) string {
	n, _, err := s.Nonce(ctx, gw)
	if err != nil {
		s.log.WarnContext(ctx, "authz.nonce_unavailable", slog.String("gateway_id", gw.ID))
	}
	return n
}

// UnknownWorkload is a gateway's report of a request it could not tie to an
// admitted instance (HR-148). The observations are UNTRUSTED.
type UnknownWorkload struct {
	Credentials
	Route, UserAgent string
}

// ReportUnknown records the report as a discovery after verifying its
// key-only proof; the request itself stays refused. The zero id means the
// sighting was only counted.
func (s *Service) ReportUnknown(ctx context.Context, gw Gateway, u UnknownWorkload) (ids.UUID, error) {
	if s.workloads == nil {
		return ids.UUID{}, errors.New("authority: workload identity is not configured")
	}
	return s.workloads.Discover(ctx, gw.Org, iapp.DiscoverInput{
		Request: pap.Request{Method: u.Method, URL: u.URL, BodySHA256: u.BodySHA256, Token: u.Token},
		Proof:   u.Proof, Gateway: gw.ID, Route: u.Route, ClientAddress: u.ClientAddress, UserAgent: u.UserAgent,
	})
}
