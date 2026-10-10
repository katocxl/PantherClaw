// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestIntHoldReadsTheTransactionsLatestRequest: the decision pipeline's
// reads of approvals (G0 M5 part 2): the latest request of (run, action)
// with its open evidence question and the context its display was rendered
// with, the variants of its grant, operation and target, the approvals of
// the last 30 days for the same operation and target, the org's hold
// settings, and the people around a child run.
func TestIntHoldReadsTheTransactionsLatestRequest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	g := w.grant("1000.00")
	run, action, txn := w.run(g.ID, ids.UUID{}), ids.NewV7(), ids.NewV7()
	exec(t, w.pool, w.org, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision,
		reason_code, gateway_id, state, target_type, target_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create',
		'REQUIRE_APPROVAL', 'REFUND_OVER_50', 'gw', 'OPEN', 'payments.charge', 'ch_1')`, w.org, txn, run, action, make([]byte, 32))
	key := sha256.Sum256([]byte("variant"))
	const request = `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id,
		grant_id, grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash,
		action_ir, deadline_at, created_at) VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $8,
		'\x7b7d', '[{"kind":"approval","role":"approver","count":1}]', $9, $7, '\x7b7d',
		date_trunc('second', now()) + interval '1 hour', $10)`
	older, newer := ids.NewV7(), ids.NewV7()
	b1, b2 := sha256.Sum256([]byte("b1")), sha256.Sum256([]byte("b2"))
	exec(t, w.pool, w.org, request, w.org, older, w.agent, txn, run, g.ID.UUID(), key[:], b1[:], `{}`, time.Now().Add(-time.Minute))
	exec(t, w.pool, w.org, `UPDATE pc.approval_requests SET state = 'INVALIDATED', end_reason = 'GRANT_REVISED', ended_at = now(),
		approved_at = now() - interval '30 seconds', consume_by = now() + interval '10 minutes' WHERE id = $1`, older)
	display := `{"variants": [{"request": "` + older.String() + `", "created": "2026-10-10T11:00:00Z", "state": "INVALIDATED"}],
		"context_not_precedent": []}`
	exec(t, w.pool, w.org, request, w.org, newer, w.agent, txn, run, g.ID.UUID(), key[:], b2[:], display, time.Now())
	cli := ids.NewV7()
	exec(t, w.pool, w.org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '{}', $4, now() + interval '1 day')`, w.org, cli, w.alice, b1[:])
	exec(t, w.pool, w.org, `UPDATE pc.approval_requests SET state = 'EVIDENCE_REQUESTED', evidence_deadline_at = now() + interval '30 minutes'
		WHERE id = $1`, newer)
	exec(t, w.pool, w.org, `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, cli_session_id, kind, reason_code)
		VALUES ($1, $2, $3, $4, $5, 'REQUEST_EVIDENCE', 'WHY_NEEDED')`, w.org, ids.NewV7(), newer, w.alice, cli)

	r := &pgauthority.Reader{Pool: w.pool}
	h, err := r.Hold(ctx, w.org, run, action)
	if err != nil || h == nil {
		t.Fatalf("hold %+v, %v", h, err)
	}
	if h.ID != newer || h.State != apdomain.StateEvidenceRequested || h.Binding != b2 || h.Question != "WHY_NEEDED" ||
		h.EvidenceDeadline == nil || len(h.Variants) != 1 || h.Variants[0].Request != older.String() {
		t.Fatalf("hold = %+v", h)
	}
	if none, err := r.Hold(ctx, w.org, run, ids.NewV7()); none != nil || err != nil {
		t.Fatalf("another action's hold: %+v, %v", none, err)
	}

	variants, approved, err := r.Variants(ctx, w.org, key, "payments.refund.create", actionir.Target{Type: "payments.charge", ID: "ch_1"}, time.Now())
	if err != nil || len(variants) != 2 || variants[0].Request != newer.String() || len(approved) != 1 || approved[0].Request != older.String() {
		t.Fatalf("variants %+v, approved %+v, %v", variants, approved, err)
	}
	if _, approved, _ := r.Variants(ctx, w.org, key, "payments.refund.create", actionir.Target{Type: "payments.charge", ID: "ch_2"}, time.Now()); len(approved) != 0 {
		t.Fatalf("another target's approvals: %+v", approved)
	}

	if s, err := r.HoldSettings(ctx, w.org); err != nil || s.HoldDeadline != 0 {
		t.Fatalf("default settings %+v, %v", s, err)
	}
	exec(t, w.pool, w.org, `INSERT INTO pc.waitlist_settings (org_id, hold_deadline_s, updated_by) VALUES ($1, 1800, 'test')`, w.org)
	if s, _ := r.HoldSettings(ctx, w.org); s.HoldDeadline != 30*time.Minute {
		t.Fatalf("settings %+v", s)
	}

	child := w.run(g.ID, run)
	got, err := r.Run(ctx, w.org, child)
	if err != nil {
		t.Fatal(err)
	}
	alice := gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}
	if got.Launcher.Kind != gdomain.PrincipalInstance || len(got.Ancestors) != 2 || got.Ancestors[0] != alice || got.Ancestors[1] != alice {
		t.Fatalf("child run %+v", got)
	}
}
