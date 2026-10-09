// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgbudgets_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

var day = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

func newOrg(t *testing.T, p *db.Pool) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org); err != nil {
			return err
		}
		return dbq.New(tx).InsertContainment(ctx, org)
	}); err != nil {
		t.Fatal(err)
	}
	return org
}

func debit(kind string, rank int, rule, limit string) bdomain.Debit {
	owner := bdomain.Owner{Kind: kind, ID: ids.NewV7(), Rank: rank}
	lim := money.MustParse(limit)
	return bdomain.Debit{
		Ref:      bdomain.Ref{Owner: owner, Rule: rule, Key: bdomain.KeyHash(owner, rule, "k"), Start: day},
		Currency: "USD", Limit: &lim, Amount: money.MustParse("1"), Period: bdomain.PeriodDay,
	}
}

// TestHR048_NoOverspendAcrossAncestorsUnder1000Goroutines: 1,000 parallel
// transactions each reserve 1 USD on a guardrail account, a parent grant's
// task budget and one of two children's budgets, in the fixed lock order.
// No account goes over its limit, no transaction deadlocks, and the
// accounts agree with the number of successes.
func TestHR048_NoOverspendAcrossAncestorsUnder1000Goroutines(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	guard := debit("envelope", 0, "org_daily", "700")
	parent := debit("grant", 1, "task", "500")
	children := []bdomain.Debit{debit("grant", 2, "task", "300"), debit("grant", 2, "task", "300")}
	all := []bdomain.Debit{guard, parent, children[0], children[1]}
	rows, err := pgbudgets.Ensure(ctx, p, org, all, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wins [2]atomic.Int64
	var deadlocks atomic.Int64
	var wg sync.WaitGroup
	for i := range 1000 {
		c := i % 2
		// Each goroutine lists its accounts in another order; only Lines'
		// fixed order keeps them from deadlocking.
		orders := [][]bdomain.Debit{{children[c], parent, guard}, {guard, parent, children[c]}, {parent, children[c], guard}}
		lines := pgbudgets.Lines(orders[i%3], nil, rows)
		wg.Go(func() {
			err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
				return pgbudgets.ReserveLines(ctx, dbq.New(tx), org, lines)
			})
			switch {
			case err == nil:
				wins[c].Add(1)
			case errors.Is(err, pgbudgets.ErrExhausted):
			case db.IsDeadlock(err):
				deadlocks.Add(1)
			default:
				t.Errorf("reservation: %v", err)
			}
		})
	}
	wg.Wait()
	if deadlocks.Load() > 0 {
		t.Fatalf("%d deadlocks: the lock order is not fixed", deadlocks.Load())
	}
	total := wins[0].Load() + wins[1].Load()
	if total != 500 || wins[0].Load() > 300 || wins[1].Load() > 300 {
		t.Fatalf("successes %d + %d, want 500 in total and at most 300 each", wins[0].Load(), wins[1].Load())
	}
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		acc, _, _, err := pgbudgets.Usage(ctx, dbq.New(tx), org, all, nil)
		if err != nil {
			return err
		}
		if got := acc[parent.Ref].Reserved; got.Cmp(money.MustParse("500")) != 0 {
			t.Errorf("parent reserved %s, want 500", got)
		}
		if got := acc[guard.Ref].Reserved; got.Cmp(money.MustParse("500")) != 0 {
			t.Errorf("guardrail reserved %s, want 500", got)
		}
		for i, c := range children {
			if got := acc[c.Ref].ReservedCount; got != wins[i].Load() {
				t.Errorf("child %d has %d reservations, %d won", i, got, wins[i].Load())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHR049_CountersHoldUnderConcurrency: a count limit of 3 with at most 2
// outstanding admits exactly 2 of 50 parallel reservations.
func TestHR049_CountersHoldUnderConcurrency(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	owner := bdomain.Owner{Kind: "grant", ID: ids.NewV7(), Rank: 1}
	two := int64(2)
	ctr := bdomain.CounterDebit{
		Ref:    bdomain.Ref{Owner: owner, Rule: "per_charge", Key: bdomain.KeyHash(owner, "per_charge", "ch_1"), Start: day},
		Window: bdomain.WindowDay, Max: 3, MaxOutstanding: &two,
	}
	rows, err := pgbudgets.Ensure(ctx, p, org, nil, []bdomain.CounterDebit{ctr})
	if err != nil {
		t.Fatal(err)
	}
	lines := pgbudgets.Lines(nil, []bdomain.CounterDebit{ctr}, rows)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
				return pgbudgets.ReserveLines(ctx, dbq.New(tx), org, lines)
			}); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 2 {
		t.Fatalf("%d reservations admitted, the outstanding limit is 2", wins.Load())
	}
}

func TestT023_CounterCardinalityIsCapped(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	owner := bdomain.Owner{Kind: "envelope", ID: ids.NewV7()}
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.counters (org_id, id, owner_kind, owner_id, rule, key_hash, window_start, rank)
			SELECT $1, gen_random_uuid(), 'envelope', $2, 'per_customer', sha256(i::text::bytea), $3, 0
			FROM generate_series(1, $4) AS i`, org, owner.ID, day, bdomain.MaxCounterRows)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctr := bdomain.CounterDebit{Ref: bdomain.Ref{Owner: owner, Rule: "per_customer", Key: bdomain.KeyHash(owner, "per_customer", "new"), Start: day}, Max: 3}
	if _, err := pgbudgets.Ensure(ctx, p, org, nil, []bdomain.CounterDebit{ctr}); !errors.Is(err, pgbudgets.ErrCapacity) {
		t.Fatalf("a counter past its cardinality cap: %v", err)
	}
}
