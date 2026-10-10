// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// preparing counts a Store's Prepare calls and the errors of its Finalize
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

// daily gives the scenario's grant a daily task budget and a daily task
// counter, so every refund of a day reserves the same two rows.
func daily(t *testing.T) (*pipelinetest.Scenario, ids.UUID, *preparing) {
	t.Helper()
	s, g, run := scenario(t)
	lim, err := gdomain.DecodeLimits([]byte(`{
	  "budgets": [{"id": "daily", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "1000", "period": "day"}],
	  "counters": [{"id": "per_day", "operations": ["payments.refund.create"], "key": "task", "window": "day", "max": "100"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g.Revision, g.Limits = 2, lim
	s.W.Grants.Put(g)
	st := &preparing{Store: s.W}
	s.Authority.Store = st
	return s, run, st
}

// budgetRef is the daily budget's row ref for a refund decided now.
func budgetRef(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) bdomain.Ref {
	t.Helper()
	ev, err := s.Authority.Pipeline.Evaluate(context.Background(), s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "1.00")))
	if err != nil || len(ev.Plan.Budgets) != 1 {
		t.Fatalf("plan: %v %+v", err, ev)
	}
	return ev.Plan.Budgets[0].Ref
}

// TestFinalizeReservesOnTheRowsTheEvaluationFound: once a period's budget
// account and counter rows exist, a permit reserves on the rows the
// evaluation found, without Prepare; the first refund of a new period
// prepares its new rows.
func TestFinalizeReservesOnTheRowsTheEvaluationFound(t *testing.T) {
	s, run, st := daily(t)
	permit := func(charge, amount string) {
		t.Helper()
		if r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund(charge, amount))); r.Permit == "" {
			t.Fatalf("%s: %s %s", charge, r.Decision, decisive(r))
		}
	}
	permit("ch_1", "30.00")
	if st.prepares != 1 {
		t.Fatalf("the first refund of the day prepared %d times, want 1", st.prepares)
	}
	permit("ch_2", "20.00")
	permit("ch_3", "5.00")
	if st.prepares != 1 {
		t.Fatalf("refunds on existing rows prepared %d times in all, want only the first", st.prepares)
	}
	if a := s.W.AccountState(budgetRef(t, s, run)); a.Reserved.String() != "55" || a.ReservedCount != 3 {
		t.Fatalf("the found row holds every reservation: reserved %s over %d", a.Reserved, a.ReservedCount)
	}

	s.W.Advance(24 * time.Hour)
	s.Refundable("ch_1")
	permit("ch_1", "7.00")
	if st.prepares != 2 {
		t.Fatalf("a new period prepared %d times in all, want 2", st.prepares)
	}
	if a := s.W.AccountState(budgetRef(t, s, run)); a.Reserved.String() != "7" || a.ReservedCount != 1 {
		t.Fatalf("the new period's row: reserved %s over %d", a.Reserved, a.ReservedCount)
	}
}

// TestFinalizeFailsClosedWhenAFoundRowIsGone: a row the evaluation found
// but that is gone by the finalization reserves nothing and issues no
// permit (ErrExhausted); the next evaluation does not find it and prepares
// it again.
func TestFinalizeFailsClosedWhenAFoundRowIsGone(t *testing.T) {
	s, run, st := daily(t)
	if r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00"))); r.Permit == "" {
		t.Fatalf("first: %s", decisive(r))
	}
	ref := budgetRef(t, s, run)
	st.before = func() { s.W.DeleteRow(ref) }
	st.errs = nil
	r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "20.00")))
	if r.Permit == "" {
		t.Fatalf("after the row was prepared again: %s %s", r.Decision, decisive(r))
	}
	if len(st.errs) != 2 || !errors.Is(st.errs[0], finalize.ErrExhausted) || st.errs[1] != nil {
		t.Fatalf("finalizations %v, want ErrExhausted and then success", st.errs)
	}
	if st.prepares != 2 {
		t.Fatalf("prepared %d times, want the first refund and the re-evaluation", st.prepares)
	}
	if a := s.W.AccountState(ref); a.Reserved.String() != "20" || a.ReservedCount != 1 {
		t.Fatalf("the permit's reservation is on the new row: reserved %s over %d", a.Reserved, a.ReservedCount)
	}
}
