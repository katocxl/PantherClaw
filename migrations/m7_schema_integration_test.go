// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M7 track A (G0
// M7): the application enforces the same rules first. Names are prefixed m7
// so that they never collide with other milestones' schema tests in this
// package.

type m7Fixture struct {
	m5p2Fixture
	gateway, connection string
	permit, attempt     string
}

const (
	m7Ledger       = `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'receipt.test', 'test', 'test', '\x7b7d')`
	m7Verification = `INSERT INTO pc.verifications (org_id, id, purpose, transaction_id, connection_id, operation, request,
		next_at, deadline_at, window_start, window_end) VALUES ($1, $2, $3, $4, $5, 'payments.refund.get', '{}', now(),
		now() + interval '10 minutes', $6, $7)`
	m7Lease = `UPDATE pc.verifications SET state = 'LEASED', lease_hash = $2, leased_by = $3, leased_at = now(),
		lease_expires_at = now() + $4::interval WHERE id = $1`
	m7Observation = `INSERT INTO pc.observations (org_id, id, source, transaction_id, verification_id, gateway_id, outcome,
		found) VALUES ($1, $2, $3, $4, $5, $6, $7, true)`
	m7Task    = `INSERT INTO pc.reconciliation_tasks (org_id, id, transaction_id, kind) VALUES ($1, $2, $3, $4)`
	m7Release = `UPDATE pc.reconciliation_tasks SET state = 'NOT_OCCURRED', resolved_via = 'person', user_id = $2,
		session_id = $3, credential_id = $4, authenticator_data = $5, client_data_json = '\x7b7d', signature = '\x01',
		basis = $6, resolved_at = now() WHERE id = $1`
)

// newM7Fixture extends the M6 fixture (org, user, credential, session,
// gateway, connection) with the M5 part 2 agent, run, grant and transaction,
// and gives the transaction a permit that reached the target and an
// attempt the gateway recorded.
func newM7Fixture(t *testing.T, p *db.Pool) m7Fixture {
	t.Helper()
	m6 := newM6Fixture(t, p)
	f := m7Fixture{m5p2Fixture: newM5p2Fixture(t, m6.m5Fixture), gateway: m6.gateway, connection: m6.connection,
		permit: m5ID(), attempt: m5ID()}
	f.mustExec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at,
		finished_at) VALUES ($1, $2, $3, $4, 1, 'DISPATCHED', now() + interval '5 seconds', now(), now())`,
		f.org, f.permit, f.txn, f.gateway)
	f.mustExec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status,
		target_ref) VALUES ($1, $2, $3, $4, 'accepted', 200, 're_1')`, f.org, f.attempt, f.permit, f.txn)
	return f
}

func (f m7Fixture) ledger(t *testing.T) string {
	t.Helper()
	id := m5ID()
	f.mustExec(t, m7Ledger, f.org, id)
	return id
}

func (f m7Fixture) verification(t *testing.T, purpose string) string {
	t.Helper()
	id := m5ID()
	if purpose == "target_log" {
		f.mustExec(t, m7Verification, f.org, id, purpose, nil, f.connection, "2026-10-10T00:00:00Z", "2026-10-10T00:15:00Z")
	} else {
		f.mustExec(t, m7Verification, f.org, id, purpose, f.txn, f.connection, nil, nil)
	}
	return id
}

func TestHR192_SweptAttemptsRecordOnlyAnUnknownOutcome(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	const insert = `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status,
		recorded_by) VALUES ($1, $2, $3, $4, $5, $6, 'sweeper')`
	other := m5ID()
	f.mustExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'ALLOWED', 'gw')`,
		f.org, other, f.run, m5ID(), m5Secret(20))
	permit := m5ID()
	f.mustExec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at,
		finished_at) VALUES ($1, $2, $3, 'gw', 1, 'UNKNOWN', now(), now(), now())`, f.org, permit, other)
	f.want(t, m5Check, "a swept attempt that claims acceptance", insert, f.org, m5ID(), permit, other, "accepted", nil)
	f.want(t, m5Check, "a swept attempt with a target status", insert, f.org, m5ID(), permit, other, "unknown", 504)
	f.mustExec(t, insert, f.org, m5ID(), permit, other, "unknown", nil)
	f.want(t, m5Unique, "a second attempt for one permit", insert, f.org, m5ID(), permit, other, "unknown", nil)
}

func TestHR055_M7EvidenceIsAppendOnly(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	f.mustExec(t, `INSERT INTO pc.execution_receipts (org_id, attempt_id, transaction_id, permit_id, receipt_jws,
		ledger_entry_id) VALUES ($1, $2, $3, $4, 'eyJhbGciOiJFZERTQSJ9.e30.sig', $5)`, f.org, f.attempt, f.txn, f.permit, f.ledger(t))
	f.mustExec(t, `INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, level_achieved, basis,
		receipt_jws, ledger_entry_id) VALUES ($1, $2, 1, 'CONFIRMED', 'acceptance', 'follow_up', 'verifier',
		'eyJhbGciOiJFZERTQSJ9.e30.sig', $3)`, f.org, f.txn, f.ledger(t))
	v := f.verification(t, "follow_up")
	f.mustExec(t, m7Observation, f.org, m5ID(), "verifier", f.txn, v, f.gateway, nil)
	for _, table := range []string{"execution_receipts", "effect_receipts", "observations", "transaction_links", "target_log_runs"} {
		f.want(t, m5Denied, "UPDATE "+table, "UPDATE pc."+table+" SET org_id = org_id")
		f.want(t, m5Denied, "DELETE "+table, "DELETE FROM pc."+table)
	}
	for _, table := range []string{"verifications", "reconciliation_tasks", "unreceipted_effects"} {
		f.want(t, m5Denied, "DELETE "+table, "DELETE FROM pc."+table)
	}
	f.want(t, m5Denied, "a task's transaction cannot change", "UPDATE pc.reconciliation_tasks SET transaction_id = transaction_id")
	f.want(t, m5Denied, "a verification's request cannot change", "UPDATE pc.verifications SET request = request")
	f.want(t, m5Check, "an effect receipt in an unknown state", `INSERT INTO pc.effect_receipts (org_id, transaction_id, seq,
		state, level_required, basis, receipt_jws, ledger_entry_id) VALUES ($1, $2, 2, 'SUCCESS', 'acceptance', 'verifier',
		'eyJhbGciOiJFZERTQSJ9.e30.sig', $3)`, f.org, f.txn, f.ledger(t))
}

func TestHR190_VerificationLeasesAreShortAndSingleUseInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	v := f.verification(t, "follow_up")
	f.want(t, m5Unique, "a second open task of one purpose", m7Verification, f.org, m5ID(), "follow_up", f.txn,
		f.connection, nil, nil)
	f.verification(t, "reconcile")
	f.want(t, m5Check, "a lease longer than 30 seconds", m7Lease, v, m5Secret(1), f.gateway, "31 seconds")
	f.want(t, m5Check, "a lease without its hash",
		"UPDATE pc.verifications SET state = 'LEASED', leased_by = $2, leased_at = now(), lease_expires_at = now() + interval '30 seconds' WHERE id = $1",
		v, f.gateway)
	f.mustExec(t, m7Lease, v, m5Secret(1), f.gateway, "30 seconds")
	w := f.verification(t, "target_log")
	f.want(t, m5Unique, "one lease secret for two tasks", m7Lease, w, m5Secret(1), f.gateway, "30 seconds")
	f.want(t, m5Check, "a target-log task bound to a transaction", m7Verification, f.org, m5ID(), "target_log", f.txn,
		f.connection, "2026-10-10T00:00:00Z", "2026-10-10T00:15:00Z")
	f.want(t, m5Check, "a follow-up task without a transaction", m7Verification, f.org, m5ID(), "follow_up", nil,
		f.connection, nil, nil)
	f.want(t, m5Check, "a finished task without its time", "UPDATE pc.verifications SET state = 'DONE' WHERE id = $1", w)
	f.want(t, m5Check, "an operation that is not a dotted name", `INSERT INTO pc.verifications (org_id, id, purpose,
		transaction_id, connection_id, operation, request, next_at, deadline_at) VALUES ($1, $2, 'reconcile', $3, $4,
		'GET /v1/refunds', '{}', now(), now() + interval '1 minute')`, f.org, m5ID(), f.txn, f.connection)

	var canSeeHash bool
	d.AdminQueryRow(t, "SELECT has_column_privilege('pc_audit_ro', 'pc.verifications', 'lease_hash', 'SELECT')", nil, &canSeeHash)
	if canSeeHash {
		t.Fatal("pc_audit_ro can read lease hashes")
	}
}

func TestHR191_ObservationsComeFromKnownSourcesInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	v := f.verification(t, "follow_up")
	f.mustExec(t, m7Observation, f.org, m5ID(), "late_report", f.txn, nil, f.gateway, "accepted")
	f.want(t, m5Check, "a late report without its outcome", m7Observation, f.org, m5ID(), "late_report", f.txn, nil, f.gateway, nil)
	f.want(t, m5Check, "a verifier observation without its task", m7Observation, f.org, m5ID(), "verifier", f.txn, nil, f.gateway, nil)
	f.want(t, m5Check, "an observation from the agent", m7Observation, f.org, m5ID(), "agent", f.txn, v, f.gateway, nil)
	f.want(t, m5Check, "a body stored as fields", `INSERT INTO pc.observations (org_id, id, source, transaction_id,
		verification_id, gateway_id, fields) VALUES ($1, $2, 'verifier', $3, $4, $5, '"raw body"')`, f.org, m5ID(), f.txn, v, f.gateway)
}

func TestHR192_ReleaseNeedsAPersonAnAssertionAndABasisInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	task := m5ID()
	f.mustExec(t, m7Task, f.org, task, f.txn, "unknown_outcome")
	f.want(t, m5Unique, "a second open task of one kind", m7Task, f.org, m5ID(), f.txn, "unknown_outcome")
	f.mustExec(t, m7Task, f.org, m5ID(), f.txn, "conflicting_effect")

	v := f.verification(t, "reconcile")
	obs := m5ID()
	f.mustExec(t, m7Observation, f.org, obs, "verifier", f.txn, v, f.gateway, nil)
	f.want(t, m5Check, "evidence that releases", `UPDATE pc.reconciliation_tasks SET state = 'NOT_OCCURRED',
		resolved_via = 'verifier', observation_id = $2, resolved_at = now() WHERE id = $1`, task, obs)
	f.want(t, m5Check, "evidence that names no observation", `UPDATE pc.reconciliation_tasks SET state = 'OCCURRED',
		resolved_via = 'verifier', resolved_at = now() WHERE id = $1`, task)
	f.want(t, m5Check, "a person resolving without a basis", `UPDATE pc.reconciliation_tasks SET state = 'OCCURRED',
		resolved_via = 'person', user_id = $2, resolved_at = now() WHERE id = $1`, task, f.user)
	f.want(t, m5Check, "a release without an assertion", `UPDATE pc.reconciliation_tasks SET state = 'NOT_OCCURRED',
		resolved_via = 'person', user_id = $2, basis = 'no refund in a complete listing', resolved_at = now() WHERE id = $1`,
		task, f.user)
	f.want(t, m5Check, "a release without a basis", m7Release, task, f.user, f.session, f.cred, m7Bytes(37), nil)
	f.mustExec(t, m7Release, task, f.user, f.session, f.cred, m7Bytes(37), "no refund in a complete listing")
	f.mustExec(t, m7Task, f.org, m5ID(), f.txn, "unknown_outcome") // the released one is no longer open
}

func m7Bytes(n int) []byte { return m6Bytes(n, 1) }

func TestHR193_TransactionLinksJoinTwoTransactionsOnce(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	later := m5ID()
	f.mustExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'ALLOWED', 'gw')`,
		f.org, later, f.run, m5ID(), m5Secret(21))
	const link = `INSERT INTO pc.transaction_links (org_id, from_transaction_id, to_transaction_id, kind, created_by)
		VALUES ($1, $2, $3, $4, 'test')`
	f.want(t, m5Check, "a transaction compensating itself", link, f.org, f.txn, f.txn, "compensates")
	f.want(t, m5Check, "an unknown link kind", link, f.org, later, f.txn, "reverses")
	f.mustExec(t, link, f.org, later, f.txn, "compensates")
	f.want(t, m5Unique, "the same link twice", link, f.org, later, f.txn, "recovers")
}

func TestHR112_UnreceiptedEffectsAreOnePerObject(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	v := f.verification(t, "target_log")
	const insert = `INSERT INTO pc.unreceipted_effects (org_id, id, connection_id, operation, object_ref, verification_id)
		VALUES ($1, $2, $3, 'payments.refund.create', $4, $5)`
	f.mustExec(t, insert, f.org, m5ID(), f.connection, "re_out_of_band", v)
	f.want(t, m5Unique, "one object reported twice", insert, f.org, m5ID(), f.connection, "re_out_of_band", v)
	f.want(t, m5Check, "acknowledged by nobody",
		"UPDATE pc.unreceipted_effects SET state = 'ACKNOWLEDGED', acknowledged_at = now()")
	f.mustExec(t, "UPDATE pc.unreceipted_effects SET state = 'ACKNOWLEDGED', acknowledged_by = 'user:alice', acknowledged_at = now()")
	f.want(t, m5Check, "a run that matched more than it saw", `INSERT INTO pc.target_log_runs (org_id, verification_id,
		connection_id, window_start, window_end, items_seen, matched, unmatched, complete) VALUES ($1, $2, $3,
		'2026-10-10T00:00:00Z', '2026-10-10T00:15:00Z', 1, 1, 1, true)`, f.org, v, f.connection)
}

func TestHR054_VerificationsDueAreListedAcrossOrgs(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := newM7Fixture(t, p)
	quiet := newM7Fixture(t, p)
	v := f.verification(t, "follow_up")
	quiet.verification(t, "follow_up")
	f.mustExec(t, m7Lease, v, m5Secret(2), f.gateway, "1 second")
	f.mustExec(t, "UPDATE pc.verifications SET leased_at = leased_at - interval '1 minute', lease_expires_at = lease_expires_at - interval '1 minute' WHERE id = $1", v)

	refs, err := p.CrossOrgList(context.Background(), db.ListVerificationsDue, 100)
	if err != nil {
		t.Fatal(err)
	}
	var orgs []string
	for _, r := range refs {
		orgs = append(orgs, r.Org.String())
	}
	if !slices.Contains(orgs, f.org.String()) || slices.Contains(orgs, quiet.org.String()) {
		t.Fatalf("verifications_due listed %v; want %s and not %s", orgs, f.org, quiet.org)
	}
}
