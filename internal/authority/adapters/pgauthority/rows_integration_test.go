// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// preparing counts the Store's Prepare calls and the errors of its Finalize
// calls; before, when set, runs once before the next Finalize.
type preparing struct {
	finalize.Store
	mu       sync.Mutex
	prepares int
	errs     []error
	before   func()
}

func (p *preparing) Prepare(ctx context.Context, org ids.OrgID, plan gdomain.Plan) ([]finalize.Row, error) {
	p.mu.Lock()
	p.prepares++
	p.mu.Unlock()
	return p.Store.Prepare(ctx, org, plan)
}

func (p *preparing) Finalize(ctx context.Context, org ids.OrgID, w finalize.Write) error {
	p.mu.Lock()
	before := p.before
	p.before = nil
	p.mu.Unlock()
	if before != nil {
		before()
	}
	err := p.Store.Finalize(ctx, org, w)
	p.mu.Lock()
	p.errs = append(p.errs, err)
	p.mu.Unlock()
	return err
}

// accounts returns the org's budget account ids and their reserved totals.
func (w *world) accounts() map[ids.UUID]string {
	w.t.Helper()
	out := map[ids.UUID]string{}
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT id, reserved::text FROM pc.budget_accounts")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id ids.UUID
			var reserved string
			if err := rows.Scan(&id, &reserved); err != nil {
				return err
			}
			out[id] = reserved
		}
		return rows.Err()
	}); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// TestIntReservesOnTheRowsTheSnapshotFound: once the task budget's account
// exists, a permit reserves on the row the evaluation's snapshot found,
// without Prepare.
func TestIntReservesOnTheRowsTheSnapshotFound(t *testing.T) {
	w := newWorld(t)
	st := &preparing{Store: w.auth.Store}
	w.auth.Store = st
	w.refundable("ch_1", "ch_2", "ch_3")
	run := w.run(w.grant("500").ID, ids.UUID{})
	for _, c := range []string{"ch_1", "ch_2", "ch_3"} {
		if r := w.authorize(w.request(run, ids.NewV7(), c, "10.00")); r.Permit == "" {
			t.Fatalf("%s: %s %s", c, r.Decision, decisive(r))
		}
	}
	if st.prepares != 1 {
		t.Fatalf("prepared %d times, want only for the first refund", st.prepares)
	}
	if acc := w.accounts(); len(acc) != 1 {
		t.Fatalf("accounts %v, want the one task budget", acc)
	}
	if res, _ := w.budget(); res != "30" {
		t.Fatalf("reserved %s, want every refund on the one row", res)
	}
}

// TestIntAFoundRowDeletedBeforeFinalizeFailsClosed: the application cannot
// delete budget accounts, but if one the snapshot found is deleted anyway
// before the finalization, the finalization's conditional update matches
// no row and rolls everything back (no permit, no reservation); the next
// evaluation does not find the row and prepares a new one.
func TestIntAFoundRowDeletedBeforeFinalizeFailsClosed(t *testing.T) {
	w := newWorld(t)
	st := &preparing{Store: w.auth.Store}
	w.auth.Store = st
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("500").ID, ids.UUID{})
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00")); r.Permit == "" {
		t.Fatalf("first: %s %s", r.Decision, decisive(r))
	}
	var old ids.UUID
	for id := range w.accounts() {
		old = id
	}
	st.before = func() {
		w.db.AdminExec(t, "DELETE FROM pc.reservations WHERE account_id = $1", old)
		w.db.AdminExec(t, "DELETE FROM pc.budget_accounts WHERE id = $1", old)
	}
	st.errs = nil
	r := w.authorize(w.request(run, ids.NewV7(), "ch_2", "20.00"))
	if r.Permit == "" {
		t.Fatalf("after the row was prepared again: %s %s", r.Decision, decisive(r))
	}
	if len(st.errs) != 2 || !errors.Is(st.errs[0], finalize.ErrExhausted) || st.errs[1] != nil {
		t.Fatalf("finalizations %v, want ErrExhausted and then success", st.errs)
	}
	if st.prepares != 2 {
		t.Fatalf("prepared %d times, want the first refund and the re-evaluation", st.prepares)
	}
	acc := w.accounts()
	if _, ok := acc[old]; ok || len(acc) != 1 {
		t.Fatalf("accounts %v, want one new row", acc)
	}
	var permits, reservations int
	var on ids.UUID
	w.db.AdminQueryRow(t, `SELECT count(DISTINCT p.id), count(r.id), min(r.account_id::text)::uuid FROM pc.permits p
		LEFT JOIN pc.reservations r ON r.org_id = p.org_id AND r.permit_id = p.id WHERE p.org_id = $1 AND p.transaction_id = $2`,
		[]any{w.org, r.TransactionID}, &permits, &reservations, &on)
	if _, ok := acc[on]; permits != 1 || reservations != 1 || !ok {
		t.Fatalf("the transaction has %d permits and %d reservations on %s, want one of each on the new row %v", permits, reservations, on, acc)
	}
}
