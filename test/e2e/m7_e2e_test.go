// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
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

// TestE2E_M7_AnEffectWithoutAReceiptIsReported: a refund made at the
// target without PantherClaw (its own console, or a leaked credential)
// shows up in the connection's target log with no receipt to match, and is
// reported as an effect without a receipt; the refund made through the
// gateway is matched (HR-112).
func TestE2E_M7_AnEffectWithoutAReceiptIsReported(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK {
		t.Fatalf("refund: %d %+v", code, r)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.simURL+"/v1/refunds",
		strings.NewReader(`{"charge":"ch_9","amount":"75.00","currency":"USD","reason":"requested_by_customer"}`))
	req.Header.Set("Idempotency-Key", "console-0001")
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("out-of-band refund: %v %v", res, err)
	}
	_ = res.Body.Close()

	// The worker schedules target logs every 15 minutes; here, as often as
	// the last task ends, until a run has seen both refunds.
	logs := &txapp.Service{Store: &pgtransactions.Store{Pool: s.db.AppPool(t)}}
	deadline := time.Now().Add(45 * time.Second)
	for s.row(t, "SELECT coalesce(max(items_seen), 0)::text FROM pc.target_log_runs") != "2" {
		if time.Now().After(deadline) {
			t.Fatal("no target-log run saw both refunds")
		}
		if _, err := logs.ScheduleTargetLogs(context.Background(), s.org); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if got := s.row(t, "SELECT string_agg(coalesce(correlation, ''), ',') FROM pc.unreceipted_effects"); got != "console-0001" {
		t.Fatalf("unreceipted effects %q", got)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.security.effect_without_receipt'"); got != "1" {
		t.Fatalf("%s security events", got)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.notifications WHERE type = 'security.effect_without_receipt'"); got != "1" {
		t.Fatalf("%s notifications to admins", got)
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
	// Either evidence may find it first: the verifier's lookup, or the
	// connection's target log (scheduled when the server starts); both
	// resolve only towards occurred.
	s.eventually(t, "OCCURRED", "SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID)
	if via := s.row(t, "SELECT resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID); via != "verifier" && via != "target_log" {
		t.Fatalf("resolved via %q, want evidence", via)
	}
	s.eventually(t, "CONFIRMED", "SELECT state FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" {
		t.Fatalf("after reconciling: reserved %s spent %s, want committed", reserved, spent)
	}
}
