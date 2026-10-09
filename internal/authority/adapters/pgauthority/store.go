// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgauthority is the PostgreSQL side of the M4 Transaction
// Authority: Store implements finalize.Store (the finalization transaction
// and settlement, design decisions 15-18) and Reader implements
// pipeline.Reader over the other modules' stores.
package pgauthority

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const receiptKindDecision = "receipt.decision"

// Store implements finalize.Store.
type Store struct {
	Pool *db.Pool
}

var _ finalize.Store = (*Store)(nil)

// Lookup implements finalize.Store.
func (s *Store) Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	var out *finalize.Stored
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetDecision(ctx, org, run, action)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &finalize.Stored{
			TransactionID: row.ID, ActionHash: hex.EncodeToString(row.ActionHash), Decision: decision(row.Decision),
			Reason: row.ReasonCode, Final: row.State == "FINAL", Evaluations: int(row.Evaluations), Receipt: row.Receipt,
		}
		return nil
	})
	return out, err
}

// Prepare implements finalize.Store.
func (s *Store) Prepare(ctx context.Context, org ids.OrgID, plan gdomain.Plan) ([]finalize.Row, error) {
	rows, err := pgbudgets.Ensure(ctx, s.Pool, org, plan.Budgets, plan.Counters)
	if errors.Is(err, pgbudgets.ErrCapacity) {
		return nil, finalize.ErrConflict // the next evaluation explains it
	}
	if err != nil {
		return nil, err
	}
	var out []finalize.Row
	for ref, id := range rows.Accounts {
		out = append(out, finalize.Row{Ref: ref, Kind: bdomain.KindBudget, ID: id})
	}
	for ref, id := range rows.Counters {
		out = append(out, finalize.Row{Ref: ref, Kind: bdomain.KindCounter, ID: id})
	}
	return out, nil
}

// Finalize implements finalize.Store: one transaction, in the lock order.
func (s *Store) Finalize(ctx context.Context, org ids.OrgID, w finalize.Write) error {
	ev := w.Eval
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if w.Permit != nil {
			if err := checkAuthority(ctx, q, org, ev); err != nil {
				return err
			}
		}
		if err := s.idempotency(ctx, q, org, w); err != nil {
			return err
		}
		if w.Permit != nil && w.Claim != nil {
			if err := claim(ctx, q, org, w, ev); err != nil {
				return err
			}
		}
		// The receipt shows each budget as read just before the reservation
		// plus this action, so the reservation can stay the last statement.
		states, err := budgetStates(ctx, q, org, ev)
		if err != nil {
			return err
		}
		receipt, err := w.Sign(states)
		if err != nil {
			return err
		}
		if err := writeReceipt(ctx, tx, org, w.TransactionID, w.Evaluation, w.GatewayID, receipt); err != nil {
			return err
		}
		if w.Permit != nil {
			rows := pgbudgets.Rows{Accounts: map[bdomain.Ref]ids.UUID{}, Counters: map[bdomain.Ref]ids.UUID{}}
			for _, r := range w.Rows {
				if r.Kind == bdomain.KindCounter {
					rows.Counters[r.Ref] = r.ID
				} else {
					rows.Accounts[r.Ref] = r.ID
				}
			}
			lines := pgbudgets.Lines(ev.Plan.Budgets, ev.Plan.Counters, rows)
			if err := q.InsertPermitForTransaction(ctx, dbq.InsertPermitForTransactionParams{
				OrgID: org, ID: w.Permit.ID, TransactionID: w.TransactionID, GatewayID: w.Permit.GatewayID,
				Epoch: w.Permit.Epoch, ExpiresAt: w.Permit.ExpiresAt,
			}); err != nil {
				return err
			}
			if err := pgbudgets.Record(ctx, q, org, w.TransactionID, w.Permit.ID, lines); err != nil {
				return err
			}
			// Budget last: the hot rows are locked only until COMMIT.
			if err := pgbudgets.ReserveLines(ctx, q, org, lines); err != nil {
				if errors.Is(err, pgbudgets.ErrExhausted) {
					return finalize.ErrExhausted
				}
				return err
			}
		}
		return nil
	})
	if db.IsUniqueViolation(err) {
		return finalize.ErrDuplicate
	}
	return err
}

// checkAuthority takes the containment row FOR SHARE first and then checks
// that the epoch, every grant and every guardrail are as evaluated (design
// decision 8): a removal of authority either finished before, and the
// revisions differ, or waits for this transaction and its epoch increment
// makes the permit fail BeginDispatch.
func checkAuthority(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) error {
	cont, err := q.ShareContainment(ctx, org)
	if err != nil {
		return fmt.Errorf("authority: containment: %w", err)
	}
	if cont.Epoch != ev.Epoch || cont.KillSwitch {
		return finalize.ErrConflict
	}
	leaf, ok := ev.Chain.Leaf()
	if !ok {
		return finalize.ErrConflict
	}
	rows, err := q.GetGrantChain(ctx, org, leaf.ID.UUID())
	if err != nil {
		return err
	}
	var cur gdomain.Chain
	for _, r := range rows {
		if r.State != string(gdomain.StateActive) {
			return finalize.ErrConflict
		}
		id, err := gdomain.ParseGrantID(r.ID.String())
		if err != nil {
			return err
		}
		cur.Grants = append(cur.Grants, gdomain.Grant{ID: id, Revision: int(r.CurrentRevision)})
	}
	keys := make([]string, 0, len(ev.Chain.Envelopes))
	for _, e := range ev.Chain.Envelopes {
		keys = append(keys, gpg.ScopeKey(e.Scope))
	}
	envs, err := q.GetEnvelopes(ctx, org, keys)
	if err != nil {
		return err
	}
	for _, e := range envs {
		id, err := gdomain.ParseEnvelopeID(e.ID.String())
		if err != nil {
			return err
		}
		cur.Envelopes = append(cur.Envelopes, gdomain.Envelope{ID: id, Revision: int(e.Revision), Scope: gdomain.Scope{Kind: gdomain.ScopeKind(e.ScopeKind)}})
	}
	if !sameVersions(cur.Versions(), ev.Chain.Versions()) {
		return finalize.ErrConflict
	}
	return nil
}

func sameVersions(a, b []gdomain.Version) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Store) idempotency(ctx context.Context, q *dbq.Queries, org ids.OrgID, w finalize.Write) error {
	ev := w.Eval
	state := "OPEN"
	if w.Final {
		state = "FINAL"
	}
	var grantID *ids.UUID
	var grantRev *int32
	if leaf, ok := ev.Chain.Leaf(); ok {
		g, r := leaf.ID.UUID(), int32(leaf.Revision) //nolint:gosec // small
		grantID, grantRev = &g, &r
	}
	basis := ev.Basis.Digest()
	effective, err := hex.DecodeString(ev.EffectiveHash)
	if err != nil {
		return err
	}
	if w.Prev == nil {
		act, err := hex.DecodeString(ev.ActionHash)
		if err != nil {
			return err
		}
		var dedupe *string
		if ev.DedupeKey != "" {
			k := ev.DedupeKey
			dedupe = &k
		}
		return q.InsertDecision(ctx, dbq.InsertDecisionParams{
			OrgID: org, ID: w.TransactionID, RunID: ev.RunID, ActionID: ev.ActionID, ActionHash: act, Operation: ev.Operation,
			Decision: string(ev.Decision), ReasonCode: w.Reason, GatewayID: w.GatewayID, State: state,
			GrantID: grantID, GrantRevision: grantRev, BasisDigest: &basis, EffectiveHash: effective, DedupeKey: dedupe,
		})
	}
	return expect(q.UpdateDecision(ctx, dbq.UpdateDecisionParams{
		Decision: string(ev.Decision), ReasonCode: w.Reason, State: state, Evaluations: int32(w.Evaluation), //nolint:gosec // ≤ 33
		GrantID: grantID, GrantRevision: grantRev, BasisDigest: &basis, EffectiveHash: effective,
		OrgID: org, ID: w.TransactionID, PrevEvaluations: int32(w.Prev.Evaluations), //nolint:gosec // ≤ 32
	}))
}

// claim takes the dedupe key for this transaction, or parks the request
// when an earlier attempt holds it (HR-007). The row lock serializes
// identical actions: the second waits for the first to commit and then
// sees its claim.
func claim(ctx context.Context, q *dbq.Queries, org ids.OrgID, w finalize.Write, ev *pipeline.Evaluation) error {
	if err := q.InsertDedupeClaim(ctx, org, w.Claim.Key, w.TransactionID); err != nil {
		return err
	}
	row, err := q.LockDedupeClaim(ctx, org, w.Claim.Key)
	if err != nil {
		return err
	}
	if row.TransactionID == w.TransactionID {
		return nil
	}
	c := &pipeline.Claim{TransactionID: row.TransactionID, State: pipeline.ClaimState(row.State), At: row.ChangedAt}
	if parked, _ := pipeline.Parked(c, ev.ActionID, ev.Now, ev.RepeatWindow); parked {
		return finalize.ErrParked
	}
	return expect(q.TakeDedupeClaim(ctx, w.TransactionID, org, w.Claim.Key))
}

func budgetStates(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) ([]finalize.BudgetState, error) {
	if len(ev.Plan.Budgets) == 0 {
		return nil, nil
	}
	acc, _, _, err := pgbudgets.Usage(ctx, q, org, ev.Plan.Budgets, nil)
	if err != nil {
		return nil, err
	}
	var out []finalize.BudgetState
	for _, d := range ev.Plan.Budgets {
		a := acc[d.Ref]
		a.Limit, a.MaxCount = d.Limit, d.MaxCount
		if ev.Permits() {
			a.Reserved, _ = a.Reserved.Add(d.Amount)
			a.ReservedCount++
		}
		st := finalize.BudgetState{
			Level: d.Ref.Owner.ID.String(), Rule: d.Ref.Rule, Currency: string(d.Currency),
			Reserved: a.Reserved.String(), Spent: a.Spent.String(),
		}
		amt, cnt := a.Available()
		if amt != nil {
			st.Available = amt.String()
		}
		if cnt != nil {
			st.Count = fmt.Sprint(*cnt)
		}
		out = append(out, st)
	}
	return out, nil
}

func writeReceipt(ctx context.Context, tx db.TenantTx, org ids.OrgID, txn ids.UUID, evaluation int, gateway string, r finalize.Receipt) error {
	entry, err := ledger.Append(ctx, tx, receiptKindDecision, evdomain.Actor{Type: "gateway", ID: gateway}, r.Body)
	if err != nil {
		return err
	}
	return dbq.New(tx).InsertEvaluationReceipt(ctx, dbq.InsertEvaluationReceiptParams{
		OrgID: org, TransactionID: txn, Evaluation: int32(evaluation), ReceiptJws: r.JWS, LedgerEntryID: entry.ID, //nolint:gosec // ≤ 33
	})
}

// Tamper implements finalize.Store.
func (s *Store) Tamper(ctx context.Context, org ids.OrgID, prev finalize.Stored, receipt *finalize.Receipt, gatewayID string) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "security.action_tampered", Actor: evdomain.Actor{Type: "gateway", ID: gatewayID}, Outcome: audit.Denied,
			ReasonCode: "ACTION_TAMPERED", Object: &audit.Object{Type: "transaction", ID: prev.TransactionID.String()},
		}); err != nil {
			return err
		}
		if prev.Final || receipt == nil {
			return nil
		}
		if err := expect(dbq.New(tx).UpdateDecision(ctx, dbq.UpdateDecisionParams{
			Decision: "DENY", ReasonCode: "ACTION_TAMPERED", State: "FINAL", Evaluations: int32(prev.Evaluations + 1), //nolint:gosec // ≤ 33
			OrgID: org, ID: prev.TransactionID, PrevEvaluations: int32(prev.Evaluations), //nolint:gosec // ≤ 32
		})); err != nil {
			return err
		}
		return writeReceipt(ctx, tx, org, prev.TransactionID, prev.Evaluations+1, gatewayID, *receipt)
	})
}

// BeginDispatch implements finalize.Store (HR-001).
func (s *Store) BeginDispatch(ctx context.Context, org ids.OrgID, gatewayID string, permit ids.UUID, epoch int64) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, err := q.BeginDispatch(ctx, dbq.BeginDispatchParams{OrgID: org, ID: permit, GatewayID: gatewayID, Epoch: epoch})
		if err == nil {
			return nil
		}
		if !db.IsNoRows(err) {
			return err
		}
		st, err := q.GetPermit(ctx, org, permit)
		switch {
		case db.IsNoRows(err):
			return finalize.ErrPermitUnknown
		case err != nil:
			return err
		case st.GatewayID != gatewayID:
			return finalize.ErrPermitUnknown
		case st.State != "ISSUED":
			return finalize.ErrPermitUsed
		case st.KillSwitch:
			return finalize.ErrKillSwitch
		case st.Expired:
			return finalize.ErrPermitExpired
		}
		return finalize.ErrEpochStale
	})
}

// RecordExecution implements finalize.Store.
func (s *Store) RecordExecution(ctx context.Context, org ids.OrgID, gatewayID string, permit ids.UUID, o finalize.Outcome) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		to := "DISPATCHED"
		if o == finalize.Unknown {
			to = "UNKNOWN"
		}
		txn, err := q.FinishPermitForTransaction(ctx, dbq.FinishPermitForTransactionParams{ToState: to, OrgID: org, ID: permit, GatewayID: gatewayID})
		if db.IsNoRows(err) {
			return finalize.ErrNotDispatching
		}
		if err != nil {
			return err
		}
		if err := q.InsertExecutionAttempt(ctx, dbq.InsertExecutionAttemptParams{
			OrgID: org, ID: ids.NewV7(), PermitID: permit, TransactionID: txn, Outcome: string(o),
		}); err != nil {
			return err
		}
		switch o {
		case finalize.Accepted:
			if err := pgbudgets.Settle(ctx, q, org, permit, bdomain.Commit); err != nil {
				return err
			}
			return q.SettleDedupeClaim(ctx, string(pipeline.ClaimSucceeded), org, txn)
		case finalize.Failed:
			if err := pgbudgets.Settle(ctx, q, org, permit, bdomain.Release); err != nil {
				return err
			}
			return q.SettleDedupeClaim(ctx, string(pipeline.ClaimReleased), org, txn)
		case finalize.Unknown: // reservations and claim stay held (HR-003, F115)
		}
		return nil
	})
}

// Sweep implements finalize.Store (HR-003).
func (s *Store) Sweep(ctx context.Context, org ids.OrgID, staleAfter time.Duration) (int, int, error) {
	var released, unknown int
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		expired, err := q.ReleaseExpiredIssued(ctx, org)
		if err != nil {
			return err
		}
		for _, p := range expired {
			if err := pgbudgets.Settle(ctx, q, org, p.ID, bdomain.Release); err != nil {
				return err
			}
			if err := q.SettleDedupeClaim(ctx, string(pipeline.ClaimReleased), org, p.TransactionID); err != nil {
				return err
			}
		}
		stale, err := q.MarkStaleDispatching(ctx, org, staleAfter.Seconds())
		released, unknown = len(expired), len(stale)
		return err
	})
	return released, unknown, err
}

func expect(tag interface{ RowsAffected() int64 }, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return finalize.ErrConflict
	}
	return nil
}

func decision(s string) adomain.Decision { return adomain.Decision(s) }
