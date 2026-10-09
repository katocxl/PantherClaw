// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package invariants_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// TestINV06_BudgetsAreConcurrencySafe: parallel refunds from a parent run
// and two child runs, whose grants have their own budgets under the
// parent's shared one, never overspend any budget (HR-048). The database
// version with 1,000 goroutines is TestHR048 in the authority adapters.
func TestINV06_BudgetsAreConcurrencySafe(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s := pipelinetest.NewScenario(rt, nil)
		parentLimit := rapid.IntRange(50, 400).Draw(rt, "parentLimit")
		childLimit := rapid.IntRange(10, 200).Draw(rt, "childLimit")
		parent := s.Grant(pipelinetest.RootBounds, s.Alice)
		parent.Revision, parent.Limits = 2, limits(rt, parentLimit)
		s.W.Grants.Put(parent)
		runs := []ids.UUID{s.Run(parent.ID, s.Alice)}
		for range 2 {
			child := parent
			child.ID, child.Revision, child.Parent, child.Depth, child.Limits = gdomain.NewGrantID(), 1, parent.ID, 1, limits(rt, childLimit)
			child.ExpiresAt = pipelinetest.Start.Add(12 * time.Hour)
			s.W.Grants.Put(child)
			runs = append(runs, s.Run(child.ID, s.Alice))
		}
		type win struct {
			run    int
			amount money.Decimal
		}
		var mu sync.Mutex
		var wins []win
		var wg sync.WaitGroup
		for i := range 40 {
			amount := fmt.Sprintf("%d.00", rapid.IntRange(1, 60).Draw(rt, "amount"))
			r := i % len(runs)
			charge := fmt.Sprintf("ch_%d", 1+i%3)
			req := s.Request(runs[r], ids.NewV7(), "create_refund", pipelinetest.Refund(charge, amount)+"")
			wg.Go(func() {
				res, err := s.Authority.Authorize(context.Background(), s.Gateway, req)
				if err == nil && res.Permit != "" {
					mu.Lock()
					wins = append(wins, win{r, money.MustParse(amount)})
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		total := money.Decimal{}
		perChild := map[int]money.Decimal{}
		for _, w := range wins {
			total, _ = total.Add(w.amount)
			if w.run > 0 {
				perChild[w.run], _ = perChild[w.run].Add(w.amount)
			}
		}
		if total.Cmp(money.MustParse(fmt.Sprint(parentLimit))) > 0 {
			rt.Fatalf("permits for %s against a shared budget of %d", total, parentLimit)
		}
		for r, sum := range perChild {
			if sum.Cmp(money.MustParse(fmt.Sprint(childLimit))) > 0 {
				rt.Fatalf("child run %d got permits for %s against its budget of %d", r, sum, childLimit)
			}
		}
	})
}

func limits(t pipelinetest.TB, limit int) gdomain.Limits {
	l, err := gdomain.DecodeLimits(fmt.Appendf(nil, `{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "%d", "period": "none"}]}`, limit))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestINV07_DecisionIsNotExecutionIsNotEffect: an ALLOW issues a permit and
// nothing more; nothing counts as dispatched until BeginDispatch, and
// nothing is spent until an accepted outcome is recorded.
func TestINV07_DecisionIsNotExecutionIsNotEffect(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	g.Revision, g.Limits = 2, limits(t, 100)
	s.W.Grants.Put(g)
	run := s.Run(g.ID, s.Alice)
	ctx := context.Background()
	res := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if res.Decision != adomain.Allow || s.W.PermitState(res.PermitID) != "ISSUED" {
		t.Fatalf("decision %s permit %s", res.Decision, s.W.PermitState(res.PermitID))
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Accepted}); !errors.Is(err, finalize.ErrNotDispatching) {
		t.Fatalf("an outcome was recorded for a permit never dispatched: %v", err)
	}
	ev, err := s.Authority.Pipeline.Evaluate(ctx, s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "1.00")))
	if err != nil {
		t.Fatal(err)
	}
	ref := ev.Plan.Budgets[0].Ref
	if a := s.W.AccountState(ref); !a.Spent.IsZero() || a.Reserved.IsZero() {
		t.Fatalf("an ALLOW reserves; it spends nothing: %+v", a)
	}
	if err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch); err != nil {
		t.Fatal(err)
	}
	if s.W.PermitState(res.PermitID) != "DISPATCHING" {
		t.Fatal("BeginDispatch is the commit point")
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Accepted}); err != nil {
		t.Fatal(err)
	}
	if a := s.W.AccountState(ref); a.Spent.Cmp(money.MustParse("30")) != 0 || !a.Reserved.IsZero() {
		t.Fatalf("an accepted outcome commits the reservation: %+v", a)
	}
}

// TestINV09_RetriesAreNotNewPermission: however an agent resubmits (the
// same ids, the same ids with a changed action, or new ids for the same
// irreversible refund), no (run, action) gets a second permit, and an
// identical refund gets no second permit while the first is unsettled.
func TestINV09_RetriesAreNotNewPermission(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s := pipelinetest.NewScenario(rt, nil)
		run := s.Run(s.Grant(pipelinetest.RootBounds, s.Alice).ID, s.Alice)
		first := ids.NewV7()
		permitsByAction := map[ids.UUID]int{}
		identical := 0
		for range rapid.IntRange(1, 12).Draw(rt, "attempts") {
			act, amount := first, "30.00"
			switch rapid.IntRange(0, 2).Draw(rt, "kind") {
			case 1:
				amount = "31.00" // the same ids, another action
			case 2:
				act = ids.NewV7() // new ids, the same refund
			}
			res := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", amount)))
			if res.Permit != "" {
				permitsByAction[act]++
				if amount == "30.00" {
					identical++
				}
			}
		}
		for act, n := range permitsByAction {
			if n > 1 {
				rt.Fatalf("action %s got %d permits", act, n)
			}
		}
		if identical > 1 {
			rt.Fatalf("an identical irreversible refund got %d permits while the first was unsettled", identical)
		}
	})
}

// TestINV11_ReceiptIntegrityIsNotProofOfEffect: the decision receipt
// records a decision (and its basis), never a dispatch or an effect, and
// never the agent's own text.
func TestINV11_ReceiptIntegrityIsNotProofOfEffect(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	run := s.Run(s.Grant(pipelinetest.RootBounds, s.Alice).ID, s.Alice)
	res := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	var r finalize.DecisionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(res.Receipt), &r); err != nil {
		t.Fatal(err)
	}
	if r.Pap.Kind != "decision" || r.Pap.BasisDigest != res.BasisDigest || r.Pap.Act != res.ActionHash {
		t.Fatalf("receipt %+v", r.Pap)
	}
	raw := string(pipelinetest.Payload(res.Receipt))
	for _, claim := range []string{`"outcome"`, `"accepted"`, `"effect"`, `"dispatched_at"`} {
		if strings.Contains(raw, claim) {
			t.Fatalf("a decision receipt claims %s", claim)
		}
	}
}
