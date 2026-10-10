// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	notifdomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// fakeNotifier renders each message from its template, as the real
// service does, and records it.
type fakeNotifier struct {
	mu   sync.Mutex
	sent []notifapp.Message
	link []string
}

func (n *fakeNotifier) Enqueue(_ context.Context, _ db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error) {
	r, err := notifdomain.Render(m.Type, m.Params)
	if err != nil {
		return notifapp.Enqueued{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent, n.link = append(n.sent, m), append(n.link, r.Link)
	return notifapp.Enqueued{Notification: ids.NewV7()}, nil
}

// rfx adds a team in a business unit to the waitlist fixture, moves the
// agent there, and binds people at different scopes.
type rfx struct {
	*wfx
	team, bu, env ids.UUID
	n             *fakeNotifier
	router        *waitlist.Router
}

func newRFx(t *testing.T) *rfx {
	t.Helper()
	f := &rfx{wfx: newWFx(t), team: ids.NewV7(), bu: ids.NewV7(), n: &fakeNotifier{}}
	f.exec("INSERT INTO pc.business_units (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", f.org, f.bu)
	f.exec("INSERT INTO pc.teams (org_id, id, business_unit_id, slug, name) VALUES ($1, $2, $3, 'refunds', 'Refunds')", f.org, f.team, f.bu)
	f.d.AdminExec(t, `UPDATE pc.agents SET state = 'CLAIMED', team_id = $1, owner_user_id = $3, execution_context = 'service', claimed_at = now(),
		environment_id = (SELECT r.environment_id FROM pc.runs r WHERE r.org_id = $2 AND r.agent_id = pc.agents.id LIMIT 1)
		WHERE org_id = $2`, f.team, f.org, f.ann)
	f.router = &waitlist.Router{Pool: f.p, Notify: f.n}
	return f
}

// person adds an enabled user bound to role at scope ("ORG", "BUSINESS_UNIT"
// or "TEAM"), a month ago, with a month-old key.
func (f *rfx) person(role, scope string) ids.UUID {
	f.t.Helper()
	u := ids.NewV7()
	f.exec(`INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', $3, now() - interval '30 days')`,
		f.org, u, u.String())
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - interval '30 days')`,
		f.org, ids.NewV7(), u, u[:], append(append([]byte{}, u[:]...), u[:]...))
	f.bind(u, role, scope)
	return u
}

func (f *rfx) bind(u ids.UUID, role, scope string) {
	f.t.Helper()
	var bu, team any
	switch scope {
	case "BUSINESS_UNIT":
		bu = f.bu
	case "TEAM":
		team = f.team
	}
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, business_unit_id, team_id, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'test', now() - interval '30 days')`, f.org, ids.NewV7(), role, u, scope, bu, team)
}

// hold opens an ACTION_HOLD entry for a request needing one approver.
func (f *rfx) hold() (entry, request ids.UUID) {
	f.t.Helper()
	request, entry = ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		SELECT $1, $2, 'ACTION', r.agent_id, $3, 1, r.id, $4, 1, $5, 'payments.refund.create', $5, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1,"sources":[]}]', '{}', $5, '\x7b7d', date_trunc('second', now()) + interval '1 hour'
		FROM pc.runs r WHERE r.id = $6`, f.org, request, f.txn, f.grant, append(append([]byte{}, request[:]...), request[:]...), f.run)
	f.exec(`INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, deadline_at)
		SELECT $1, $2, 'ACTION_HOLD', 'approval_request', $3, agent_id, run_id, transaction_id, deadline_at
		FROM pc.approval_requests WHERE id = $3`, f.org, entry, request)
	return entry, request
}

func (f *rfx) route() int {
	f.t.Helper()
	n, err := f.router.RouteOrg(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// routes lists an entry's recorded recipients as "kind:user".
func (f *rfx) routes(entry ids.UUID) []string {
	f.t.Helper()
	var out []string
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT kind || ':' || user_id FROM pc.waitlist_routes WHERE entry_id = $1 ORDER BY 1", entry)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out
}

// TestHR173_RoutingReachesOnlyTheNearestEligibleDeciders (decision 8,
// T-061): a hold is routed to the approvers bound nearest the agent (the
// team), never to the run's launcher even when she holds the role, with a
// notice that links to the approval page; it is routed once, and the next
// step is due at half its time.
func TestHR173_RoutingReachesOnlyTheNearestEligibleDeciders(t *testing.T) {
	f := newRFx(t)
	near := f.person("approver", "TEAM")
	f.person("approver", "ORG")
	f.bind(f.ann, "approver", "TEAM") // the launcher
	entry, request := f.hold()
	if n := f.route(); n != 1 {
		t.Fatalf("routed %d entries", n)
	}
	if got := f.routes(entry); !slices.Equal(got, []string{"decider:" + near.String()}) {
		t.Fatalf("routes %v", got)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "approval.requested" || !slices.Equal(f.n.sent[0].Personal, []ids.UUID{near}) ||
		f.n.link[0] != "/approvals/"+request.String() || f.n.sent[0].Params["operation"] != "payments.refund.create" {
		t.Fatalf("notice %+v %v", f.n.sent, f.n.link)
	}
	var health string
	var half bool
	f.d.AdminQueryRow(t, `SELECT routing_health, next_step_at = created_at + (deadline_at - created_at) / 2 FROM pc.waitlist_entries WHERE id = $1`,
		[]any{entry}, &health, &half)
	if health != "OK" || !half {
		t.Fatalf("health %s, next step at half %v", health, half)
	}
	if n := f.route(); n != 0 || len(f.n.sent) != 1 {
		t.Fatalf("routed again: %d", n)
	}
}

// TestHR173_NoEligibleDeciderTellsTheAdmins (F635): a hold no one may decide
// is marked NO_ELIGIBLE_DECIDER and the org's admins are told; nobody is
// made eligible.
func TestHR173_NoEligibleDeciderTellsTheAdmins(t *testing.T) {
	f := newRFx(t)
	admin := f.person("org_admin", "ORG")
	f.bind(f.ann, "approver", "TEAM") // only the launcher holds the role
	entry, _ := f.hold()
	f.route()
	var health string
	f.d.AdminQueryRow(t, "SELECT routing_health FROM pc.waitlist_entries WHERE id = $1", []any{entry}, &health)
	if health != "NO_ELIGIBLE_DECIDER" {
		t.Fatalf("health %s", health)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "approval.unroutable" || !slices.Equal(f.n.sent[0].Personal, []ids.UUID{admin}) {
		t.Fatalf("notice %+v", f.n.sent)
	}
	if got := f.routes(entry); !slices.Equal(got, []string{"admin:" + admin.String()}) {
		t.Fatalf("routes %v", got)
	}
}

// TestHR173_OtherKindsReachTheirPermissionHolders: an unknown outcome is
// routed to the holders of incident.respond, nearest first, with a waitlist
// notice that names no amount or text.
func TestHR173_OtherKindsReachTheirPermissionHolders(t *testing.T) {
	f := newRFx(t)
	bu := f.person("responder", "BUSINESS_UNIT")
	f.person("security_admin", "ORG")
	var entry ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		entry, err = pgwaitlist.OpenReconciliation(ctx, tx, f.org, f.txn, pgwaitlist.System)
		return err
	})
	f.route()
	if got := f.routes(entry); !slices.Equal(got, []string{"decider:" + bu.String()}) {
		t.Fatalf("routes %v", got)
	}
	if len(f.n.sent) != 1 || f.n.sent[0].Type != "waitlist.entry_created" || f.n.sent[0].Params["kind"] != "RECONCILIATION" {
		t.Fatalf("notice %+v", f.n.sent)
	}
}
