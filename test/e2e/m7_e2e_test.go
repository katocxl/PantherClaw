// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// row reads one text row of the seeded org.
func (s *stack) row(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var out string
	err := s.db.AppPool(t).InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&out)
	})
	if err != nil && !db.IsNoRows(err) {
		t.Fatal(err)
	}
	return out
}

// eventually polls sql until it returns want, for at most 45 seconds.
func (s *stack) eventually(t *testing.T, want, sql string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	got := ""
	for time.Now().Before(deadline) {
		if got = s.row(t, sql, args...); got == want {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s: %q, want %q", sql, got, want)
}

// TestE2E_M7_ARefundIsConfirmedByItsVerifier: a refund through the gateway
// gets its execution receipt and, from the verifier's read through the same
// gateway, a CONFIRMED effect receipt at follow-up level (G0 M7 exit).
func TestE2E_M7_ARefundIsConfirmedByItsVerifier(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, r)
	}
	if got := s.row(t, "SELECT recorded_by || ' ' || coalesce(target_ref, '') FROM pc.execution_attempts WHERE transaction_id = $1", r.TransactionID); got[:8] != "gateway " || len(got) < 12 {
		t.Fatalf("attempt %q: no target reference", got)
	}
	s.eventually(t, "CONFIRMED follow_up verifier",
		"SELECT state || ' ' || coalesce(level_achieved, '') || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1",
		r.TransactionID)
	if got := s.row(t, "SELECT effect_state FROM pc.transactions WHERE id = $1", r.TransactionID); got != "CONFIRMED" {
		t.Fatalf("transaction effect %q", got)
	}
}

// TestE2E_M7_AnUnknownRefundIsFoundByItsVerifier: S07 with a lost answer.
// The refund happened but the gateway timed out: UNKNOWN, budget held. The
// verifier's lookup finds it by its idempotency key and resolves the
// reconciliation as occurred, committing the budget (HR-192).
func TestE2E_M7_AnUnknownRefundIsFoundByItsVerifier(t *testing.T) {
	s := start(t, options{budget: "1000.00", faults: payments.Faults{LoseRate: 1, HangFor: time.Minute}, timeout: 500 * time.Millisecond})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("lost answer: %d %+v", code, r)
	}
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "30" || spent != "0" {
		t.Fatalf("before reconciling: reserved %s spent %s", reserved, spent)
	}
	s.eventually(t, "OCCURRED verifier", "SELECT state || ' ' || coalesce(resolved_via, '') FROM pc.reconciliation_tasks WHERE transaction_id = $1",
		r.TransactionID)
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" {
		t.Fatalf("after reconciling: reserved %s spent %s, want committed", reserved, spent)
	}
	if got := s.row(t, "SELECT state FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID); got != "CONFIRMED" {
		t.Fatalf("effect %q", got)
	}
}
