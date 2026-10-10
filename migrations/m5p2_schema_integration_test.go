// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M5 part 2 (G0
// M5 part 2): the application enforces the same rules first. Names are
// prefixed m5p2 so that they never collide with other milestones' schema
// tests in this package.

type m5p2Fixture struct {
	m5Fixture
	agent, run, grant, txn string
	user2, session2        string
	cliSession             string
}

const (
	m5p2Request = `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id,
		grant_id, grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash,
		deadline_at) VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $8, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1}]', '{}', $7, date_trunc('second', now()) + $9::interval)`
	m5p2Restoration = `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by, operation,
		binding, binding_input, requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'RESTORATION', $3, $4, 'agent.restore', $5, '\x7b7d', '[{"kind":"approval","role":"approver","count":1}]',
		'{}', $5, date_trunc('second', now()) + interval '24 hours')`
	m5p2Approve = `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, session_id, cli_session_id, kind,
		requirement, credential_id, authenticator_data, client_data_json, signature)
		VALUES ($1, $2, $3, $4, $5, $6, 'APPROVE', 0, $7, $8, '\x7b7d', '\x01')`
	m5p2Decline = `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, session_id, cli_session_id, kind,
		reason_code, note) VALUES ($1, $2, $3, $4, $5, $6, 'DECLINE', $7, 'not this one')`
	m5p2Entry = `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id,
		transaction_id, requested_by, deadline_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + interval '1 hour')`
)

// newM5p2Fixture extends the M5 part 1 fixture (org, user, credential,
// browser session) with an agent, a run, its grant and an OPEN
// transaction, a second user with a browser session, and a CLI session of
// the first user.
func newM5p2Fixture(t *testing.T, f m5Fixture) m5p2Fixture {
	t.Helper()
	g := m5p2Fixture{
		m5Fixture: f, agent: m5ID(), run: m5ID(), grant: m5ID(), txn: m5ID(), user2: m5ID(),
		session2: m5ID(), cliSession: m5ID(),
	}
	env := m5ID()
	g.mustExec(t, "INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", g.org, env)
	g.mustExec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", g.org, g.agent)
	g.mustExec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, expires_at) VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`,
		g.org, g.run, g.agent, env, g.user)
	g.mustExec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, g.org, g.grant, g.agent, g.user, env)
	g.mustExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, state) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'GRANT_REQUIRES_APPROVAL',
		'gw', 'OPEN')`, g.org, g.txn, g.run, m5ID(), m5Secret(9))
	g.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", g.org, g.user2)
	g.mustExec(t, m5Session, g.org, g.session2, g.user2, m5Secret(10))
	g.mustExec(t, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '{}', $4, now() + interval '1 day')`,
		g.org, g.cliSession, g.user, m5Secret(11))
	return g
}

// request inserts a PENDING ACTION request with binding b and returns its id.
func (g m5p2Fixture) request(t *testing.T, b byte) string {
	t.Helper()
	id := m5ID()
	g.mustExec(t, m5p2Request, g.org, id, g.agent, g.txn, g.run, g.grant, m5Secret(b), m5Secret(b), "1 hour")
	return id
}

func TestHR171_ApprovalRequestsAreFixedOnceRecorded(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	req := g.request(t, 20)
	g.want(t, m5Unique, "a second live request for one transaction", m5p2Request,
		g.org, m5ID(), g.agent, g.txn, g.run, g.grant, m5Secret(21), m5Secret(21), "1 hour")
	for _, col := range []string{
		"binding", "binding_input", "requirements", "display", "display_hash", "deadline_at",
		"transaction_id", "run_id", "grant_revision", "agent_id", "subject_kind",
	} {
		g.want(t, m5Denied, "updating "+col, "UPDATE pc.approval_requests SET "+col+" = "+col+" WHERE id = $1", req)
	}
	g.want(t, m5Check, "superseded without a reason",
		"UPDATE pc.approval_requests SET state = 'SUPERSEDED', ended_at = now() WHERE id = $1", req)
	g.want(t, m5Check, "approved without its times", "UPDATE pc.approval_requests SET state = 'APPROVED' WHERE id = $1", req)
	g.want(t, m5Check, "a consume-by time after the deadline", `UPDATE pc.approval_requests SET state = 'APPROVED',
		approved_at = now(), consume_by = deadline_at + interval '1 second' WHERE id = $1`, req)
	g.want(t, m5Check, "consumed without a permit", `UPDATE pc.approval_requests SET state = 'CONSUMED', approved_at = now(),
		consume_by = now() + interval '15 minutes', consumed_at = now(), ended_at = now() WHERE id = $1`, req)
	g.want(t, m5Check, "evidence requested without an evidence deadline",
		"UPDATE pc.approval_requests SET state = 'EVIDENCE_REQUESTED' WHERE id = $1", req)
	g.mustExec(t, "UPDATE pc.approval_requests SET state = 'SUPERSEDED', end_reason = 'BINDING_CHANGED', ended_at = now() WHERE id = $1", req)
	g.request(t, 22) // the superseded request is no longer live

	g.want(t, m5Unique, "one binding twice", m5p2Restoration, g.org, m5ID(), g.agent, g.user, m5Secret(20))
	g.want(t, m5Check, "a deadline beyond 7 days", m5p2Request, g.org, m5ID(), g.agent, g.txn, g.run, g.grant, m5Secret(23), m5Secret(23), "8 days")
	g.want(t, m5Check, "a deadline in fractions of a second", m5p2Request,
		g.org, m5ID(), g.agent, g.txn, g.run, g.grant, m5Secret(24), m5Secret(24), "1 hour 0.5 seconds")
	g.want(t, m5Check, "an action request without its run", `INSERT INTO pc.approval_requests (org_id, id, subject_kind,
		agent_id, transaction_id, evaluation, grant_id, grant_revision, variant_key, operation, binding, binding_input,
		requirements, display, display_hash, deadline_at) VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, 1, $6, 'x', $6, '\x7b7d',
		'[{}]', '{}', $6, date_trunc('second', now()) + interval '1 hour')`, g.org, m5ID(), g.agent, g.txn, g.grant, m5Secret(25))

	g.mustExec(t, m5p2Restoration, g.org, m5ID(), g.agent, g.user, m5Secret(30))
	g.want(t, m5Unique, "two live restorations of one agent", m5p2Restoration, g.org, m5ID(), g.agent, g.user2, m5Secret(31))
	g.want(t, m5Check, "a restoration without its requester", `INSERT INTO pc.approval_requests (org_id, id, subject_kind,
		agent_id, operation, binding, binding_input, requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'RESTORATION', $3, 'agent.restore', $4, '\x7b7d', '[{}]', '{}', $4,
		date_trunc('second', now()) + interval '1 hour')`, g.org, m5ID(), g.agent, m5Secret(32))
}

func TestHR035_ResponsesCountOncePerPersonAndCredential(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	req := g.request(t, 40)
	authData := m5Secret(41)
	authData = append(authData, make([]byte, 5)...)
	cred2 := m5ID()
	g.mustExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key 2')`,
		g.org, cred2, g.user, m5Secret(42)[:16], m5Secret(2))
	approval := m5ID()
	g.mustExec(t, m5p2Approve, g.org, approval, req, g.user, g.session, nil, g.cred, authData)
	g.want(t, m5Unique, "the same person approving twice", m5p2Approve, g.org, m5ID(), req, g.user, g.session, nil, cred2, authData)
	g.want(t, m5Unique, "one credential counted for a second person", m5p2Approve, g.org, m5ID(), req, g.user2, g.session2, nil, g.cred, authData)
	g.want(t, m5Check, "an approval from a CLI session", m5p2Approve, g.org, m5ID(), req, g.user2, nil, g.cliSession, g.cred, authData)
	g.want(t, m5Check, "an approval without an assertion", `INSERT INTO pc.approval_responses (org_id, id, request_id,
		user_id, session_id, kind, requirement) VALUES ($1, $2, $3, $4, $5, 'APPROVE', 0)`, g.org, m5ID(), req, g.user2, g.session2)
	g.want(t, m5Check, "a decline that carries an assertion", `INSERT INTO pc.approval_responses (org_id, id, request_id,
		user_id, session_id, kind, reason_code, credential_id) VALUES ($1, $2, $3, $4, $5, 'DECLINE', 'OTHER', $6)`,
		g.org, m5ID(), req, g.user2, g.session2, g.cred)
	g.want(t, m5Check, "a decline reason off the list", m5p2Decline, g.org, m5ID(), req, g.user2, g.session2, nil, "BECAUSE")
	g.want(t, m5Check, "a response from no session", m5p2Decline, g.org, m5ID(), req, g.user2, nil, nil, "OTHER")
	g.mustExec(t, m5p2Decline, g.org, m5ID(), req, g.user, nil, g.cliSession, "TOO_RISKY") // declining from the CLI works
	g.want(t, m5Unique, "a second decline", m5p2Decline, g.org, m5ID(), req, g.user2, g.session2, nil, "OTHER")
	g.want(t, m5Check, "a note over 500 characters", `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id,
		session_id, kind, reason_code, note) VALUES ($1, $2, $3, $4, $5, 'REQUEST_EVIDENCE', 'WHY', $6)`,
		g.org, m5ID(), req, g.user2, g.session2, strings.Repeat("x", 501))

	for _, col := range []string{"kind", "signature", "requirement", "user_id", "credential_id", "note"} {
		g.want(t, m5Denied, "updating "+col, "UPDATE pc.approval_responses SET "+col+" = "+col+" WHERE id = $1", approval)
	}
	g.want(t, m5Check, "voided without a reason", "UPDATE pc.approval_responses SET voided_at = now() WHERE id = $1", approval)
	g.mustExec(t, "UPDATE pc.approval_responses SET voided_at = now(), void_reason = 'ROLE_REMOVED' WHERE id = $1", approval)
	g.want(t, m5Check, "a void is final",
		"UPDATE pc.approval_responses SET voided_at = now(), void_reason = 'USER_DISABLED' WHERE id = $1", approval)
}

func TestHR033_BindingCeremoniesSignTheBinding(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	binding := m5Secret(50)
	req := g.request(t, 50)
	const ceremony = `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge,
		approval_request_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '5 minutes')`
	first := m5ID()
	g.mustExec(t, ceremony, g.org, first, g.session, g.user, "BINDING", binding, req)
	g.mustExec(t, ceremony, g.org, m5ID(), g.session2, g.user2, "BINDING", binding, req) // two deciders sign one binding
	g.want(t, m5Unique, "two open ceremonies of one person for one request", ceremony,
		g.org, m5ID(), g.session, g.user, "BINDING", binding, req)
	g.want(t, m5Check, "a binding ceremony about nothing", ceremony, g.org, m5ID(), g.session, g.user, "BINDING", m5Secret(51), nil)
	g.want(t, m5Check, "a step-up naming a request", ceremony, g.org, m5ID(), g.session, g.user, "STEP_UP", m5Secret(52), req)
	g.mustExec(t, ceremony, g.org, m5ID(), g.session, g.user, "STEP_UP", m5Secret(53), nil)
	g.want(t, m5Unique, "registration and step-up challenges stay unique", ceremony,
		g.org, m5ID(), g.session2, g.user2, "REGISTRATION", m5Secret(53), nil)
	g.mustExec(t, "UPDATE pc.webauthn_ceremonies SET consumed_at = now() WHERE id = $1", first)
	g.mustExec(t, ceremony, g.org, m5ID(), g.session, g.user, "BINDING", binding, req) // a used ceremony frees the slot
	g.want(t, m5Denied, "a ceremony's request cannot change",
		"UPDATE pc.webauthn_ceremonies SET approval_request_id = approval_request_id WHERE id = $1", first)
}

func TestHR037_HoldSlotsStayWithinTheHardCap(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	const insert = "INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending) VALUES ($1, $2, $3, $4)"
	g.mustExec(t, insert, g.org, "grant", g.grant, 100)
	g.mustExec(t, insert, g.org, "run", g.run, 0)
	g.want(t, m5Check, "more than 100 pending holds", "UPDATE pc.hold_slots SET pending = pending + 1 WHERE scope_id = $1", g.grant)
	g.want(t, m5Check, "fewer than none", "UPDATE pc.hold_slots SET pending = pending - 1 WHERE scope_id = $1", g.run)
	g.want(t, m5Unique, "two counters for one grant", insert, g.org, "grant", g.grant, 1)
	g.want(t, m5Check, "a counter for something else", insert, g.org, "agent", g.agent, 1)
}

func TestHR172_EvidenceIsBoundedAndInsertOnly(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	req := g.request(t, 60)
	const insert = `INSERT INTO pc.approval_evidence (org_id, id, request_id, author_kind, author_user_id, note)
		VALUES ($1, $2, $3, $4, $5, $6)`
	note := m5ID()
	g.mustExec(t, insert, g.org, note, req, "user", g.user, "the customer was charged twice")
	g.want(t, m5Check, "a note over 4 KiB", insert, g.org, m5ID(), req, "user", g.user, strings.Repeat("é", 2049))
	g.want(t, m5Check, "an empty note", insert, g.org, m5ID(), req, "user", g.user, "")
	g.want(t, m5Check, "a workload note signed by a person", insert, g.org, m5ID(), req, "workload", g.user, "x")
	g.want(t, m5Denied, "evidence cannot be rewritten", "UPDATE pc.approval_evidence SET note = 'approved' WHERE id = $1", note)
}

func TestHR177_WaitlistEntriesTakeTheirShapeFromTheKind(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	req := g.request(t, 70)
	hold := m5ID()
	none := (*string)(nil)
	g.mustExec(t, m5p2Entry, g.org, hold, "ACTION_HOLD", "approval_request", req, g.agent, g.run, g.txn, none)
	g.want(t, m5Unique, "two open entries for one subject", m5p2Entry,
		g.org, m5ID(), "ACTION_HOLD", "approval_request", req, g.agent, g.run, g.txn, none)
	g.want(t, m5Check, "a hold without its transaction", m5p2Entry,
		g.org, m5ID(), "ACTION_HOLD", "approval_request", m5ID(), g.agent, g.run, nil, none)
	g.want(t, m5Check, "a hold about a grant", m5p2Entry, g.org, m5ID(), "ACTION_HOLD", "grant", g.grant, g.agent, g.run, g.txn, none)
	g.mustExec(t, m5p2Entry, g.org, m5ID(), "TOOL_REVIEW", "package_version", m5ID(), nil, nil, nil, none)
	g.want(t, m5Check, "a tool review about an agent", m5p2Entry,
		g.org, m5ID(), "TOOL_REVIEW", "package_version", m5ID(), g.agent, nil, nil, none)
	g.want(t, m5Check, "a reconciliation about another transaction", m5p2Entry,
		g.org, m5ID(), "RECONCILIATION", "transaction", m5ID(), g.agent, g.run, g.txn, none)
	g.mustExec(t, m5p2Entry, g.org, m5ID(), "RECONCILIATION", "transaction", g.txn, g.agent, g.run, g.txn, none)
	g.want(t, m5Check, "an access request nobody filed", m5p2Entry,
		g.org, m5ID(), "ACCESS_REQUEST", "grant", g.grant, g.agent, g.run, nil, none)
	by := "user:" + g.user
	g.mustExec(t, m5p2Entry, g.org, m5ID(), "ACCESS_REQUEST", "grant", g.grant, g.agent, g.run, nil, &by)
	g.want(t, m5Check, "an unknown kind", m5p2Entry, g.org, m5ID(), "OTHER", "grant", m5ID(), g.agent, g.run, nil, &by)

	for _, col := range []string{"kind", "subject_id", "deadline_at", "agent_id", "evidence", "created_at"} {
		g.want(t, m5Denied, "updating "+col, "UPDATE pc.waitlist_entries SET "+col+" = "+col+" WHERE id = $1", hold)
	}
	g.want(t, m5Check, "priority 5", "UPDATE pc.waitlist_entries SET priority = 5 WHERE id = $1", hold)
	g.want(t, m5Check, "assigned without a time", "UPDATE pc.waitlist_entries SET assignee_user_id = $2 WHERE id = $1", hold, g.user2)
	g.mustExec(t, `UPDATE pc.waitlist_entries SET priority = 1, routing_health = 'NO_ELIGIBLE_DECIDER', escalation_step = 1,
		next_step_at = now(), assignee_user_id = $2, assigned_at = now(), first_response_at = now() WHERE id = $1`, hold, g.user2)

	const route = "INSERT INTO pc.waitlist_routes (org_id, id, entry_id, step, kind, user_id, channel_id) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	g.mustExec(t, route, g.org, m5ID(), hold, 0, "decider", g.user2, nil)
	g.want(t, m5Check, "a channel route without its channel", route, g.org, m5ID(), hold, 0, "channel", g.user2, nil)
	g.want(t, m5Check, "a sixth escalation step", route, g.org, m5ID(), hold, 6, "decider", g.user2, nil)
	g.want(t, m5Denied, "routes are insert-only", "UPDATE pc.waitlist_routes SET user_id = user_id")
}

func TestHR177_WaitlistSettingsStayWithinTheDecisionBounds(t *testing.T) {
	d := dbtest.New(t)
	g := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	g.mustExec(t, `INSERT INTO pc.waitlist_settings (org_id, batch_ceilings, hold_deadline_s, max_holds_per_grant,
		min_account_age_s, updated_by) VALUES ($1, '{"USD": "100.00"}', 1800, 10, 1209600, 'test')`, g.org)
	for _, c := range []struct{ name, set string }{
		{"a hold deadline longer than an hour", "hold_deadline_s = 7200"},
		{"a consume window longer than 15 minutes", "consume_window_s = 1800"},
		{"a restoration deadline longer than 24 hours", "restoration_deadline_s = 90000"},
		{"more than 100 holds per grant", "max_holds_per_grant = 101"},
		{"more than 5 holds per run", "max_holds_per_run = 6"},
		{"an account cooldown under 7 days", "min_account_age_s = 86400"},
		{"a role cooldown under 24 hours", "min_role_age_s = 3600"},
		{"a credential cooldown under 24 hours", "min_credential_age_s = 3600"},
		{"a self-grant delay under 24 hours", "self_grant_delay_s = 3600"},
		{"ceilings that are not an object", "batch_ceilings = '[]'"},
	} {
		g.want(t, m5Check, c.name, "UPDATE pc.waitlist_settings SET "+c.set)
	}

	const chain = "INSERT INTO pc.escalation_chains (org_id, id, team_id, revision, steps, created_by) VALUES ($1, $2, NULL, $3, $4, 'test')"
	g.mustExec(t, chain, g.org, m5ID(), 1, `[{"at": 0.5}]`)
	g.want(t, m5Unique, "one revision twice", chain, g.org, m5ID(), 1, `[{"at": 0.5}]`)
	g.want(t, m5Check, "six steps", chain, g.org, m5ID(), 2, `[{},{},{},{},{},{}]`)
	g.want(t, m5Check, "no steps", chain, g.org, m5ID(), 2, `[]`)
	g.want(t, m5Denied, "chains are immutable revisions", "UPDATE pc.escalation_chains SET steps = steps")
}

func TestHR174_RequestChangesNotifyWaitersWithIdsOnly(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	g := newM5p2Fixture(t, newM5Fixture(t, p))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := p.Pgx().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN pc_wait"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "UNLISTEN *") }()

	want := g.org.String() + ":" + g.txn
	req := g.request(t, 80)
	g.mustExec(t, "UPDATE pc.approval_requests SET state = 'SUPERSEDED', end_reason = 'BINDING_CHANGED', ended_at = now() WHERE id = $1", req)
	for i := range 2 {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("notification %d: %v", i, err)
		}
		if n.Channel != "pc_wait" || n.Payload != want {
			t.Fatalf("notification %d = %s %q, want pc_wait %q (ids only, HR-056)", i, n.Channel, n.Payload, want)
		}
	}
	// A restoration has no transaction and wakes no waiter.
	g.mustExec(t, m5p2Restoration, g.org, m5ID(), g.agent, g.user, m5Secret(81))
	short, cancelShort := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelShort()
	if n, err := conn.Conn().WaitForNotification(short); err == nil {
		t.Fatalf("unexpected notification %q", n.Payload)
	}
}
