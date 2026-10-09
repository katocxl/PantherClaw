// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

func TestPeriodAndWindowStarts(t *testing.T) {
	at := time.Date(2026, 10, 9, 14, 37, 12, 0, time.FixedZone("x", 3600)) // Friday 13:37:12 UTC
	tests := []struct {
		got, want time.Time
	}{
		{PeriodDay.Start(at), time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)},
		{PeriodWeek.Start(at), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)},
		{PeriodMonth.Start(at), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{PeriodNone.Start(at), time.Unix(0, 0).UTC()},
		{WindowMinute.Start(at), time.Date(2026, 10, 9, 13, 37, 0, 0, time.UTC)},
		{WindowHour.Start(at), time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)},
		{WindowDay.Start(at), time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)},
		{WindowNone.Start(at), time.Unix(0, 0).UTC()},
	}
	for i, tt := range tests {
		if !tt.got.Equal(tt.want) {
			t.Errorf("%d: got %s, want %s", i, tt.got, tt.want)
		}
	}
	if !PeriodWeek.Start(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)).Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)) {
		t.Error("Monday starts its own week")
	}
}

func TestKeyHashSeparatesOwnersRulesAndValues(t *testing.T) {
	o1, o2 := Owner{Kind: "grant", ID: ids.NewV7()}, Owner{Kind: "grant", ID: ids.NewV7()}
	hashes := [][32]byte{KeyHash(o1, "r", "v"), KeyHash(o2, "r", "v"), KeyHash(o1, "s", "v"), KeyHash(o1, "r", "w"), KeyHash(o1, "r\x00v", "")}
	for i := range hashes {
		for j := i + 1; j < len(hashes); j++ {
			if hashes[i] == hashes[j] {
				t.Fatalf("hashes %d and %d collide", i, j)
			}
		}
	}
}

func TestHR048_LockOrderIsGuardrailsThenAncestorsFirst(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(t, "n")
		lines := make([]Line, n)
		for i := range lines {
			lines[i] = Line{Kind: Kind(rapid.IntRange(0, 1).Draw(t, "kind")), ID: ids.NewV7(), Rank: rapid.IntRange(0, 4).Draw(t, "rank")}
		}
		want := Order(lines)
		shuffled := slices.Clone(lines)
		for i := len(shuffled) - 1; i > 0; i-- {
			j := rapid.IntRange(0, i).Draw(t, "swap")
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		got := Order(shuffled)
		if !slices.EqualFunc(got, want, func(a, b Line) bool { return a.ID == b.ID }) {
			t.Fatal("the lock order depends on the input order")
		}
		for i := 1; i < len(got); i++ {
			if got[i-1].Rank > got[i].Rank {
				t.Fatalf("rank %d locked before rank %d", got[i-1].Rank, got[i].Rank)
			}
		}
	})
}

func dec(s string) *money.Decimal {
	d := money.MustParse(s)
	return &d
}

func count(n int64) *int64 { return &n }

func TestHR048_ReservationIsAllOrNothing(t *testing.T) {
	b := NewBook()
	parent, child := ids.NewV7(), ids.NewV7()
	b.Accounts[parent] = &Account{ID: parent, Rank: 1, Currency: "USD", Limit: dec("100")}
	b.Accounts[child] = &Account{ID: child, Rank: 2, Currency: "USD", Limit: dec("50")}
	lines := []Line{{Kind: KindBudget, ID: child, Rank: 2, Amount: money.MustParse("60")}, {Kind: KindBudget, ID: parent, Rank: 1, Amount: money.MustParse("60")}}
	failed, err := b.Reserve(lines)
	if !errors.Is(err, ErrExhausted) || failed.ID != child {
		t.Fatalf("Reserve = %v on %v, want the child's account exhausted", err, failed.ID)
	}
	if !b.Accounts[parent].Reserved.IsZero() {
		t.Fatal("a failed reservation left the parent debited")
	}
	lines[0].Amount, lines[1].Amount = money.MustParse("40"), money.MustParse("40")
	if _, err := b.Reserve(lines); err != nil {
		t.Fatal(err)
	}
	if amt, _ := b.Accounts[parent].Available(); amt.String() != "60" {
		t.Fatalf("the parent has %s left, want 60: a child's spending debits its ancestor", amt)
	}
	b.Settle(lines, Hold)
	if amt, _ := b.Accounts[child].Available(); amt.String() != "10" {
		t.Fatalf("an UNKNOWN outcome must keep the reservation (F115): %s left", amt)
	}
	b.Settle(lines, Commit)
	if a := b.Accounts[child]; a.Spent.String() != "40" || !a.Reserved.IsZero() || a.SpentCount != 1 {
		t.Fatalf("commit: %+v", a)
	}
}

func TestHR049_CountersAndOutstandingLimits(t *testing.T) {
	b := NewBook()
	c := ids.NewV7()
	b.Counters[c] = &Counter{ID: c, Max: 3, MaxOutstanding: count(2)}
	one := []Line{{Kind: KindCounter, ID: c}}
	for i := range 2 {
		if _, err := b.Reserve(one); err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
	}
	if _, err := b.Reserve(one); !errors.Is(err, ErrExhausted) {
		t.Fatalf("a third outstanding action: %v", err)
	}
	b.Settle(one, Commit)
	if _, err := b.Reserve(one); err != nil {
		t.Fatalf("after one settled: %v", err)
	}
	b.Settle(one, Commit)
	b.Settle(one, Commit)
	if _, err := b.Reserve(one); !errors.Is(err, ErrExhausted) {
		t.Fatalf("over the window maximum: %v", err)
	}
	if _, err := b.Check(one); !errors.Is(err, ErrExhausted) {
		t.Fatal("Check disagrees with Reserve")
	}
}

// TestPropBudgetsNeverOverspend drives random reservations and settlements
// through a chain of accounts (a guardrail, a parent and two children) and
// checks after every step that no account is over its limit, that a failed
// reservation changed nothing, and that Check agrees with Reserve.
func TestPropBudgetsNeverOverspend(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBook()
		env, parent, c1, c2, ctr := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
		b.Accounts[env] = &Account{ID: env, Rank: 0, Currency: "USD", Limit: dec(fmt.Sprint(rapid.IntRange(0, 30).Draw(t, "env")))}
		b.Accounts[parent] = &Account{ID: parent, Rank: 1, Currency: "USD", Limit: dec(fmt.Sprint(rapid.IntRange(0, 20).Draw(t, "parent"))), MaxCount: count(int64(rapid.IntRange(1, 6).Draw(t, "parentCount")))}
		b.Accounts[c1] = &Account{ID: c1, Rank: 2, Currency: "USD", Limit: dec(fmt.Sprint(rapid.IntRange(0, 15).Draw(t, "c1")))}
		b.Accounts[c2] = &Account{ID: c2, Rank: 2, Currency: "USD", MaxCount: count(int64(rapid.IntRange(1, 4).Draw(t, "c2")))}
		b.Counters[ctr] = &Counter{ID: ctr, Max: int64(rapid.IntRange(1, 5).Draw(t, "ctr"))}
		var open [][]Line
		for range rapid.IntRange(1, 40).Draw(t, "steps") {
			if len(open) > 0 && rapid.Bool().Draw(t, "settle") {
				i := rapid.IntRange(0, len(open)-1).Draw(t, "which")
				b.Settle(open[i], Outcome(rapid.IntRange(0, 2).Draw(t, "outcome")))
				open = slices.Delete(open, i, i+1)
			} else {
				amt := money.MustParse(fmt.Sprint(rapid.IntRange(0, 8).Draw(t, "amount")))
				leaf := rapid.SampledFrom([]ids.UUID{c1, c2}).Draw(t, "leaf")
				lines := []Line{
					{Kind: KindBudget, ID: leaf, Rank: 2, Amount: amt},
					{Kind: KindBudget, ID: parent, Rank: 1, Amount: amt},
					{Kind: KindBudget, ID: env, Rank: 0, Amount: amt},
					{Kind: KindCounter, ID: ctr},
				}
				before := snapshot(b)
				_, checkErr := b.Check(lines)
				_, err := b.Reserve(lines)
				if (checkErr == nil) != (err == nil) {
					t.Fatalf("Check = %v but Reserve = %v", checkErr, err)
				}
				if err != nil {
					if snapshot(b) != before {
						t.Fatal("a failed reservation changed the book")
					}
				} else {
					open = append(open, lines)
				}
			}
			for id, a := range b.Accounts {
				if amt, cnt := a.Available(); (amt != nil && amt.Sign() < 0) || (cnt != nil && *cnt < 0) {
					t.Fatalf("account %s overspent: %+v", id, a)
				}
			}
			if c := b.Counters[ctr]; c.Reserved+c.Spent > c.Max || c.Reserved < 0 {
				t.Fatalf("counter over its maximum: %+v", c)
			}
		}
	})
}

func snapshot(b *Book) string {
	s := ""
	for _, id := range slices.SortedFunc(func(yield func(ids.UUID) bool) {
		for id := range b.Accounts {
			if !yield(id) {
				return
			}
		}
	}, func(a, c ids.UUID) int { return slices.Compare(a[:], c[:]) }) {
		a := b.Accounts[id]
		s += fmt.Sprintf("%s:%s/%s/%d/%d;", id, a.Reserved, a.Spent, a.ReservedCount, a.SpentCount)
	}
	for _, c := range b.Counters {
		s += fmt.Sprintf("c%d/%d;", c.Reserved, c.Spent)
	}
	return s
}
