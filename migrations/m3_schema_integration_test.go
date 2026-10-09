// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// These tests check the schema's second line of defense for M3 (G0 M3):
// the application enforces the same rules first.

const (
	checkViolation  = "23514"
	uniqueViolation = "23505"
	denied          = "42501"
	testJKT         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
)

type fixture struct {
	p                       *db.Pool
	org                     ids.OrgID
	team, env, owner, other string
	sa, agent               string
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func (f fixture) exec(t *testing.T, sql string, args ...any) error {
	t.Helper()
	return f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func (f fixture) mustExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.exec(t, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f fixture) wantState(t *testing.T, want, name, sql string, args ...any) {
	t.Helper()
	if got := sqlState(f.exec(t, sql, args...)); got != want {
		t.Errorf("%s: SQLSTATE %q, want %q", name, got, want)
	}
}

func newID() string { return ids.NewV7().String() }

// newFixture creates, as pc_app, an org with a team, an environment, two
// users, a service account and one claimed agent.
func newFixture(t *testing.T, p *db.Pool) fixture {
	t.Helper()
	f := fixture{
		p: p, org: ids.New[ids.Org](), team: newID(), env: newID(), owner: newID(), other: newID(),
		sa: newID(), agent: newID(),
	}
	f.mustExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm3')", f.org)
	f.mustExec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", f.org, f.team)
	f.mustExec(t, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind)
		VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')`, f.org, f.env, f.team)
	for i, u := range []string{f.owner, f.other} {
		f.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)",
			f.org, u, []string{"alice", "bob"}[i])
	}
	f.mustExec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", f.org, f.sa)
	f.mustExec(t, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context,
		state, created_by, claimed_at) VALUES ($1, $2, 'coder', $3, $4, $5, 'ci', 'CLAIMED', 'test', now())`,
		f.org, f.agent, f.team, f.env, f.owner)
	return f
}

func TestHR090_ReplayStoreIsPartitionedBySlot(t *testing.T) {
	d := dbtest.New(t)
	f := newFixture(t, d.AppPool(t))
	var kind string
	var parts int
	var appOnPartition bool
	d.AdminQueryRow(t, `SELECT c.relkind::text, (SELECT count(*) FROM pg_inherits i WHERE i.inhparent = c.oid),
		has_table_privilege('pc_app', 'pc.dpop_jti_0', 'SELECT')
		FROM pg_class c WHERE c.oid = 'pc.dpop_jti'::regclass`, nil, &kind, &parts, &appOnPartition)
	if kind != "p" || parts != 10 || appOnPartition {
		t.Fatalf("dpop_jti: relkind=%s partitions=%d pc_app on partition=%v, want p, 10, false", kind, parts, appOnPartition)
	}
	const insert = "INSERT INTO pc.dpop_jti (org_id, slot, jkt, jti, nonce_minute) VALUES ($1, $2, $3, $4, $5)"
	const minute = int64(29857620)
	jti := "AAAAAAAAAAAAAAAAAAAAAAAA"
	f.mustExec(t, insert, f.org, minute%10, testJKT, jti, minute)
	f.wantState(t, uniqueViolation, "replayed proof", insert, f.org, minute%10, testJKT, jti, minute)
	f.wantState(t, checkViolation, "slot not derived from the nonce", insert, f.org, (minute+1)%10, testJKT, "B"+jti, minute)

	// The policy on the parent isolates tenants.
	g := newFixture(t, f.p)
	var n int
	if err := f.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.dpop_jti").Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("other org sees %d replay rows (err %v)", n, err)
	}
}

func TestHR140_IssuerEntriesPinAudienceAndBindingInSchema(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	other := ids.New[ids.Org]()
	const insert = `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience,
		algorithms, binding, state, proposed_by, activated_by, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'github_actions', 'https://token.actions.githubusercontent.com', $6,
		'{RS256}', $7, 'ACTIVE', 'test', 'test', now())`
	entry := newID()
	binding := `{"repository_id":"1","repository_owner_id":"2"}`
	f.wantState(t, checkViolation, "another org's audience", insert, f.org, newID(), entry, 1, f.agent,
		"pantherclaw:"+other.String(), binding)
	f.wantState(t, checkViolation, "no binding claims", insert, f.org, newID(), entry, 1, f.agent,
		"pantherclaw:"+f.org.String(), "{}")
	f.mustExec(t, insert, f.org, newID(), entry, 1, f.agent, "pantherclaw:"+f.org.String(), binding)
	f.wantState(t, uniqueViolation, "two active revisions", insert, f.org, newID(), entry, 2, f.agent,
		"pantherclaw:"+f.org.String(), binding)
}

func TestHR143_AttestationsAreSingleUseInSchema(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	rev, inst := newID(), newID()
	f.mustExec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience,
		algorithms, binding, state, proposed_by, activated_by, activated_at)
		VALUES ($1, $2, $3, 1, $4, 'kubernetes', 'cluster:prod', $5, '{RS256}', '{"namespace":"agents"}', 'ACTIVE',
		'test', 'test', now())`, f.org, rev, newID(), f.agent, "pantherclaw:"+f.org.String())
	f.mustExec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via,
		issuer_revision_id, binding, att_level, attested_until)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'attestation', $5, '{"namespace":"agents"}', 2, now() + interval '10 minutes')`,
		f.org, inst, f.agent, testJKT, rev)
	const insert = `INSERT INTO pc.attestations (org_id, id, instance_id, issuer_revision_id, issuer, token_key, claims,
		issued_at, expires_at) VALUES ($1, $2, $3, $4, 'cluster:prod', $5, '{}', now(), now() + $6::interval)`
	key := make([]byte, 32)
	f.mustExec(t, insert, f.org, newID(), inst, rev, key, "10 minutes")
	f.wantState(t, uniqueViolation, "reused attestation token", insert, f.org, newID(), inst, rev, key, "10 minutes")
	key[0] = 1
	f.wantState(t, checkViolation, "lifetime over one hour", insert, f.org, newID(), inst, rev, key, "2 hours")
	f.wantState(t, denied, "attestations are insert-only", "UPDATE pc.attestations SET claims = '{}'")
	f.wantState(t, checkViolation, "L2 without an issuer", `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt,
		public_jwk, state, enrolled_via, att_level) VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery', 2)`,
		f.org, newID(), f.agent, "x"+testJKT[1:])
}

func TestT004_EnrollmentTokensLiveAtMost15Minutes(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	const insert = `INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'test', now() + $6::interval)`
	f.mustExec(t, insert, f.org, newID(), f.agent, f.env, make([]byte, 32), "15 minutes")
	f.wantState(t, checkViolation, "16-minute token", insert, f.org, newID(), f.agent, f.env, []byte("0123456789abcdef0123456789abcdef"), "16 minutes")
}

func TestHR146_RunPrincipalIsNeverLauncherNamedInSchema(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	const insert = `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, launcher_sa_id,
		principal_user_id, principal_sa_id, principal_source, subject_issuer, subject_subject, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now() + interval '8 hours')`
	none := (*string)(nil)
	iss, sub := "https://idp.test", "bob"
	f.mustExec(t, insert, f.org, newID(), f.agent, f.env, f.owner, none, f.owner, none, "launcher", none, none)
	f.mustExec(t, insert, f.org, newID(), f.agent, f.env, none, f.sa, f.other, none, "subject_token", iss, sub)
	f.wantState(t, checkViolation, "launcher names another user", insert,
		f.org, newID(), f.agent, f.env, none, f.sa, f.other, none, "launcher", none, none)
	f.wantState(t, checkViolation, "subject token without provider identity", insert,
		f.org, newID(), f.agent, f.env, none, f.sa, f.other, none, "subject_token", none, none)
	f.wantState(t, checkViolation, "child run without a parent", insert,
		f.org, newID(), f.agent, f.env, f.owner, none, f.owner, none, "parent_run", none, none)
	f.wantState(t, checkViolation, "two launchers", insert,
		f.org, newID(), f.agent, f.env, f.owner, f.sa, f.owner, none, "launcher", none, none)
	f.wantState(t, checkViolation, "run longer than 24 hours", `INSERT INTO pc.runs (org_id, id, agent_id, environment_id,
		launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '25 hours')`, f.org, newID(), f.agent, f.env, f.owner)
}

func TestHR055_AgentChangesAreAppendOnly(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	f.mustExec(t, "INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor) VALUES ($1, $2, $3, 'agent.created', 'test')",
		f.org, newID(), f.agent)
	f.wantState(t, denied, "update history", "UPDATE pc.agent_changes SET reason = 'rewritten'")
	f.wantState(t, denied, "delete history", "DELETE FROM pc.agent_changes")
}

func TestIntAgentsSchemaInvariants(t *testing.T) {
	f := newFixture(t, dbtest.New(t).AppPool(t))
	const insert = `INSERT INTO pc.agents (org_id, id, name, team_id, owner_user_id, state, created_by, claimed_at)
		VALUES ($1, $2, 'x', $3, $4, $5, 'test', $6::timestamptz)`
	none := (*string)(nil)
	f.mustExec(t, insert, f.org, newID(), none, none, "DISCOVERED", none)
	f.wantState(t, checkViolation, "claimed without environment and context", insert,
		f.org, newID(), f.team, f.owner, "CLAIMED", "2026-10-09T00:00:00Z")
	f.wantState(t, checkViolation, "discovered with an owner", insert,
		f.org, newID(), none, f.owner, "DISCOVERED", none)
	f.wantState(t, checkViolation, "suspended without a previous state", insert,
		f.org, newID(), none, none, "SUSPENDED", none)
	const entry = `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, deadline_at)
		VALUES ($1, $2, $3, 'agent', $4, $4, now() + interval '7 days')`
	f.mustExec(t, entry, f.org, newID(), "ADMISSION", f.agent)
	f.wantState(t, uniqueViolation, "second open entry for one subject", entry, f.org, newID(), "ADMISSION", f.agent)
	f.wantState(t, checkViolation, "entry kinds arrive with M5", entry, f.org, newID(), "ACTION_HOLD", newID())
}
