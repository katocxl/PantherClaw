// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgbudgets keeps budget accounts and counters in PostgreSQL
// (HR-048, HR-049; G0 M4 part 2, design decisions 9-10). Ensure creates the
// rows a plan needs in its own short transaction; the finalization then
// calls Reserve inside its transaction, last, which applies one conditional
// update per row in the fixed (rank, id) order and records a reservation
// per row; Settle applies an outcome to every reservation of a permit.
package pgbudgets

import (
	"context"
	"errors"
	"fmt"

	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Errors.
var (
	// ErrExhausted: a row had no room left; the transaction must roll back.
	ErrExhausted = errors.New("budgets: limit reached")
	// ErrCapacity: a counter rule already tracks MaxCounterRows keys in this
	// window (T-023).
	ErrCapacity = errors.New("budgets: counter capacity reached")
)

// Rows maps the refs of a plan to their row ids.
type Rows struct {
	Accounts map[bdomain.Ref]ids.UUID
	Counters map[bdomain.Ref]ids.UUID
}

func ownerKey(r bdomain.Ref) (string, ids.UUID) { return r.Owner.Kind, r.Owner.ID }

// Ensure creates the rows of a plan that do not exist yet and resolves every
// row id, in one short transaction of its own (never inside a
// finalization, so a finalization only updates rows and cannot deadlock on
// inserts).
func Ensure(ctx context.Context, pool *db.Pool, org ids.OrgID, budgets []bdomain.Debit, counters []bdomain.CounterDebit) (Rows, error) {
	out := Rows{Accounts: map[bdomain.Ref]ids.UUID{}, Counters: map[bdomain.Ref]ids.UUID{}}
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, d := range budgets {
			kind, owner := ownerKey(d.Ref)
			var currency *string
			if d.Currency != "" {
				c := string(d.Currency)
				currency = &c
			}
			if err := q.EnsureBudgetAccount(ctx, dbq.EnsureBudgetAccountParams{
				OrgID: org, ID: ids.NewV7(), OwnerKind: kind, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:],
				PeriodStart: d.Ref.Start, Rank: int16(d.Ref.Owner.Rank), Currency: currency, //nolint:gosec // 0..5
			}); err != nil {
				return err
			}
			row, err := q.GetBudgetAccount(ctx, dbq.GetBudgetAccountParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], PeriodStart: d.Ref.Start})
			if err != nil {
				return err
			}
			out.Accounts[d.Ref] = row.ID
		}
		for _, d := range counters {
			kind, owner := ownerKey(d.Ref)
			row, err := q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
			if db.IsNoRows(err) {
				n, cerr := q.CountCounterRows(ctx, dbq.CountCounterRowsParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, WindowStart: d.Ref.Start})
				if cerr != nil {
					return cerr
				}
				if n >= bdomain.MaxCounterRows {
					return ErrCapacity
				}
				if err := q.EnsureCounter(ctx, dbq.EnsureCounterParams{
					OrgID: org, ID: ids.NewV7(), OwnerKind: kind, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:],
					WindowStart: d.Ref.Start, Rank: int16(d.Ref.Owner.Rank), //nolint:gosec // 0..5
				}); err != nil {
					return err
				}
				row, err = q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
			}
			if err != nil {
				return err
			}
			out.Counters[d.Ref] = row.ID
		}
		return nil
	})
	return out, err
}

// Usage reads what is reserved and spent on the rows of a plan, and how many
// rows each counter rule has in its window. Rows that do not exist yet have
// no usage.
func Usage(ctx context.Context, q *dbq.Queries, org ids.OrgID, budgets []bdomain.Debit, counters []bdomain.CounterDebit) (
	map[bdomain.Ref]bdomain.Account, map[bdomain.Ref]bdomain.Counter, map[bdomain.Ref]int, error,
) {
	accounts := map[bdomain.Ref]bdomain.Account{}
	ctrs := map[bdomain.Ref]bdomain.Counter{}
	rows := map[bdomain.Ref]int{}
	for _, d := range budgets {
		_, owner := ownerKey(d.Ref)
		row, err := q.GetBudgetAccount(ctx, dbq.GetBudgetAccountParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], PeriodStart: d.Ref.Start})
		if db.IsNoRows(err) {
			continue
		}
		if err != nil {
			return nil, nil, nil, err
		}
		accounts[d.Ref] = bdomain.Account{
			ID: row.ID, Reserved: row.Reserved, Spent: row.Spent,
			ReservedCount: int64(row.ReservedCount), SpentCount: int64(row.SpentCount),
		}
	}
	for _, d := range counters {
		_, owner := ownerKey(d.Ref)
		row, err := q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
		switch {
		case err == nil:
			ctrs[d.Ref] = bdomain.Counter{ID: row.ID, Reserved: int64(row.Reserved), Spent: int64(row.Spent)}
		case !db.IsNoRows(err):
			return nil, nil, nil, err
		}
		capRef := d.Ref
		capRef.Key = [32]byte{}
		n, err := q.CountCounterRows(ctx, dbq.CountCounterRowsParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, WindowStart: d.Ref.Start})
		if err != nil {
			return nil, nil, nil, err
		}
		rows[capRef] = int(n)
	}
	return accounts, ctrs, rows, nil
}

// Line is one row to reserve, with the current rule limits.
type Line struct {
	bdomain.Line
	Limit          *money.Decimal
	MaxCount       *int64
	Max            int64
	MaxOutstanding *int64
}

// Lines builds the reservation lines of a plan on resolved rows, in the lock
// order (HR-048).
func Lines(budgets []bdomain.Debit, counters []bdomain.CounterDebit, rows Rows) []Line {
	byID := map[ids.UUID]Line{}
	var plain []bdomain.Line
	for _, d := range budgets {
		id := rows.Accounts[d.Ref]
		l := bdomain.Line{Kind: bdomain.KindBudget, ID: id, Rank: d.Ref.Owner.Rank, Amount: d.Amount}
		byID[id] = Line{Line: l, Limit: d.Limit, MaxCount: d.MaxCount}
		plain = append(plain, l)
	}
	for _, d := range counters {
		id := rows.Counters[d.Ref]
		l := bdomain.Line{Kind: bdomain.KindCounter, ID: id, Rank: d.Ref.Owner.Rank}
		byID[id] = Line{Line: l, Max: d.Max, MaxOutstanding: d.MaxOutstanding}
		plain = append(plain, l)
	}
	out := make([]Line, 0, len(plain))
	for _, l := range bdomain.Order(plain) {
		out = append(out, byID[l.ID])
	}
	return out
}

// ReserveLines applies one conditional update per line, in order. The first
// that matches no row returns ErrExhausted: the caller rolls back.
func ReserveLines(ctx context.Context, q *dbq.Queries, org ids.OrgID, lines []Line) error {
	for _, l := range lines {
		var err error
		switch l.Kind {
		case bdomain.KindBudget:
			var maxCount *int32
			if l.MaxCount != nil {
				m := int32(min(*l.MaxCount, 1<<31-1)) //nolint:gosec // clamped
				maxCount = &m
			}
			err = db.ExpectOneRow(q.ReserveBudgetAccount(ctx, dbq.ReserveBudgetAccountParams{
				Amount: l.Amount, OrgID: org, ID: l.ID, LimitAmount: l.Limit, MaxCount: maxCount,
			}))
		case bdomain.KindCounter:
			var outstanding *int32
			if l.MaxOutstanding != nil {
				m := int32(min(*l.MaxOutstanding, 1<<31-1)) //nolint:gosec // clamped
				outstanding = &m
			}
			err = db.ExpectOneRow(q.ReserveCounter(ctx, dbq.ReserveCounterParams{
				OrgID: org, ID: l.ID, Max: int32(min(l.Max, 1<<31-1)), MaxOutstanding: outstanding, //nolint:gosec // clamped
			}))
		}
		if errors.Is(err, db.ErrLostRace) {
			return fmt.Errorf("%w: %s row %s", ErrExhausted, kindName(l.Kind), l.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func kindName(k bdomain.Kind) string {
	if k == bdomain.KindCounter {
		return "counter"
	}
	return "budget"
}

// Record records one reservation per line for a permit.
func Record(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn, permit ids.UUID, lines []Line) error {
	for _, l := range lines {
		p := dbq.InsertReservationParams{OrgID: org, ID: ids.NewV7(), TransactionID: txn, PermitID: permit, Amount: l.Amount}
		id := l.ID
		if l.Kind == bdomain.KindCounter {
			p.CounterID = &id
		} else {
			p.AccountID = &id
		}
		if err := q.InsertReservation(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// Settle applies an outcome to every held reservation of a permit: commit
// moves it to spent, release gives it back, hold keeps it (HR-003, F115).
func Settle(ctx context.Context, q *dbq.Queries, org ids.OrgID, permit ids.UUID, o bdomain.Outcome) error {
	if o == bdomain.Hold {
		return nil
	}
	held, err := q.ListHeldReservations(ctx, org, permit)
	if err != nil {
		return err
	}
	commit := o == bdomain.Commit
	state := "RELEASED"
	if commit {
		state = "COMMITTED"
	}
	for _, r := range held {
		if err := db.ExpectOneRow(q.SettleReservation(ctx, state, org, r.ID)); err != nil {
			return err
		}
		switch {
		case r.AccountID != nil:
			err = db.ExpectOneRow(q.SettleBudgetAccount(ctx, dbq.SettleBudgetAccountParams{Amount: r.Amount, Commit: commit, OrgID: org, ID: *r.AccountID}))
		case r.CounterID != nil:
			err = db.ExpectOneRow(q.SettleCounter(ctx, commit, org, *r.CounterID))
		}
		if err != nil {
			return fmt.Errorf("budgets: settle: %w", err)
		}
	}
	return nil
}
