// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// These tests check the schema's second line of defense for M5 part 1 (G0
// M5): the application enforces the same rules first. Names are prefixed
// m5 so that they never collide with other milestones' schema tests in this
// package.

const (
	m5Check   = "23514"
	m5Unique  = "23505"
	m5Denied  = "42501"
	m5Hash    = `'\x0000000000000000000000000000000000000000000000000000000000000000'::bytea`
	m5Session = `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), ` + m5Hash + `, now() + interval '12 hours')`
)

type m5Fixture struct {
	p          *db.Pool
	org        ids.OrgID
	user, cred string
	session    string
}

func m5State(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func (f m5Fixture) exec(sql string, args ...any) error {
	return f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func (f m5Fixture) mustExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.exec(sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f m5Fixture) want(t *testing.T, code, name, sql string, args ...any) {
	t.Helper()
	if got := m5State(f.exec(sql, args...)); got != code {
		t.Errorf("%s: SQLSTATE %q, want %q", name, got, code)
	}
}

func m5ID() string { return ids.NewV7().String() }

func m5Secret(b byte) []byte {
	s := make([]byte, 32)
	s[0] = b
	return s
}

// newM5Fixture creates, as pc_app, an org with one user, one WebAuthn
// credential and one browser session.
func newM5Fixture(t *testing.T, p *db.Pool) m5Fixture {
	t.Helper()
	f := m5Fixture{p: p, org: ids.New[ids.Org](), user: m5ID(), cred: m5ID(), session: m5ID()}
	f.mustExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm5')", f.org)
	f.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.mustExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.cred, f.user, m5Secret(1)[:16], m5Secret(2))
	f.mustExec(t, m5Session, f.org, f.session, f.user, m5Secret(3))
	return f
}

func TestHR150_SessionRowsHoldOnlyBoundedHashedSecrets(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	f.want(t, m5Unique, "two sessions with one secret", m5Session, f.org, m5ID(), f.user, m5Secret(3))
	f.want(t, m5Check, "a secret that is not a SHA-256", m5Session, f.org, m5ID(), f.user, []byte("plain"))
	f.want(t, m5Check, "longer than 12 hours",
		`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), `+m5Hash+`, now() + interval '13 hours')`, f.org, m5ID(), f.user, m5Secret(4))
	f.want(t, m5Check, "ended without a reason", "UPDATE pc.sessions SET state = 'ENDED', ended_at = now() WHERE id = $1", f.session)
	f.want(t, m5Check, "step-up without its credential", "UPDATE pc.sessions SET step_up_at = now() WHERE id = $1", f.session)
	f.want(t, m5Check, "previous secret without a rotation time",
		"UPDATE pc.sessions SET prev_secret_hash = $2 WHERE id = $1", f.session, m5Secret(5))
	f.mustExec(t, "UPDATE pc.sessions SET step_up_at = now(), step_up_credential_id = $2 WHERE id = $1", f.session, f.cred)
	f.mustExec(t, "UPDATE pc.sessions SET state = 'ENDED', end_reason = 'LOGOUT', ended_at = now() WHERE id = $1", f.session)
	f.want(t, m5Denied, "the user of a session cannot change", "UPDATE pc.sessions SET user_id = user_id WHERE id = $1", f.session)
	f.want(t, m5Denied, "the expiry cannot be extended", "UPDATE pc.sessions SET expires_at = now() WHERE id = $1", f.session)

	// The audit role sees sessions but never their secrets.
	var canSee, canSeeSecret bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.sessions', 'state', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.sessions', 'secret_hash', 'SELECT')`, nil, &canSee, &canSeeSecret)
	if !canSee || canSeeSecret {
		t.Fatalf("pc_audit_ro: state=%v secret_hash=%v, want true, false", canSee, canSeeSecret)
	}
}

func TestHR152_LoginReturnPathIsAlwaysLocal(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	const insert = `INSERT INTO pc.login_requests (org_id, id, state_hash, binding_hash, provider, next_path, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', $5, now() + interval '10 minutes')`
	f.mustExec(t, insert, f.org, m5ID(), m5Secret(1), m5Secret(2), "/account")
	for _, next := range []string{"//evil.example", `/\evil.example`, "https://evil.example", "/", "account", "/%2F"} {
		f.want(t, m5Check, "next "+next, insert, f.org, m5ID(), m5Secret(9), m5Secret(2), next)
	}
	f.want(t, m5Unique, "a reused state", insert, f.org, m5ID(), m5Secret(1), m5Secret(2), "/account")
	f.want(t, m5Check, "consumed but still holding its state",
		"UPDATE pc.login_requests SET state = 'CONSUMED', consumed_at = now()")
}

func TestHR153_CredentialIDsAreUniquePerOrgAndCeremoniesShort(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := newM5Fixture(t, p)
	const cred = `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, $6, false, false, 'none', 'key')`
	f.want(t, m5Unique, "a credential id registered twice", cred, f.org, m5ID(), f.user, m5Secret(1)[:16], m5Secret(2), -7)
	f.want(t, m5Check, "an algorithm off the list", cred, f.org, m5ID(), f.user, m5Secret(7)[:16], m5Secret(2), -36)
	f.want(t, m5Check, "a credential id under 16 bytes", cred, f.org, m5ID(), f.user, m5Secret(8)[:15], m5Secret(2), -7)
	f.want(t, m5Check, "suspended for another reason",
		"UPDATE pc.webauthn_credentials SET state = 'SUSPENDED', state_reason = 'USER_REMOVED', changed_at = now() WHERE id = $1", f.cred)
	f.want(t, m5Denied, "the public key cannot change", "UPDATE pc.webauthn_credentials SET public_key = public_key WHERE id = $1", f.cred)
	f.want(t, m5Denied, "the owner cannot change", "UPDATE pc.webauthn_credentials SET user_id = user_id WHERE id = $1", f.cred)
	// Another org may hold the same credential id: uniqueness is per org.
	newM5Fixture(t, p)

	const ceremony = `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)`
	f.mustExec(t, ceremony, f.org, m5ID(), f.session, f.user, "STEP_UP", m5Secret(1), "5 minutes")
	f.want(t, m5Check, "a ceremony longer than 5 minutes", ceremony, f.org, m5ID(), f.session, f.user, "STEP_UP", m5Secret(2), "6 minutes")
	f.want(t, m5Check, "a short challenge", ceremony, f.org, m5ID(), f.session, f.user, "STEP_UP", []byte("short"), "1 minute")
	f.want(t, m5Check, "an unknown purpose", ceremony, f.org, m5ID(), f.session, f.user, "APPROVAL", m5Secret(3), "1 minute")
	f.want(t, m5Unique, "a reused challenge", ceremony, f.org, m5ID(), f.session, f.user, "REGISTRATION", m5Secret(1), "1 minute")
	f.want(t, m5Denied, "a ceremony's challenge cannot change", "UPDATE pc.webauthn_ceremonies SET challenge = challenge")
}

func TestHR157_ChannelSecretsAreShapedAndHiddenFromAudit(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	const insert = `INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, recipient_role, url, secret, created_by)
		VALUES ($1, $2, $3, $4, '{security.*}', $5, $6, $7, 'test')`
	secret := make([]byte, 64)
	f.mustExec(t, insert, f.org, m5ID(), "hooks", "webhook", nil, "https://hooks.example/pc", secret)
	f.mustExec(t, insert, f.org, m5ID(), "chat", "slack", nil, nil, secret)
	f.mustExec(t, insert, f.org, m5ID(), "admins", "email", "org_admin", nil, nil)
	f.mustExec(t, insert, f.org, m5ID(), "audit-log", "log", nil, nil, nil)
	f.want(t, m5Check, "a webhook over http", insert, f.org, m5ID(), "plain", "webhook", nil, "http://hooks.example/pc", secret)
	f.want(t, m5Check, "a webhook without a secret", insert, f.org, m5ID(), "nosecret", "webhook", nil, "https://hooks.example/pc", nil)
	f.want(t, m5Check, "a Slack channel without its URL secret", insert, f.org, m5ID(), "chat2", "slack", nil, nil, nil)
	f.want(t, m5Check, "an email channel without a role", insert, f.org, m5ID(), "mail", "email", nil, nil, nil)
	f.want(t, m5Check, "a log channel holding a secret", insert, f.org, m5ID(), "log2", "log", nil, nil, secret)
	f.want(t, m5Unique, "two live channels with one name", insert, f.org, m5ID(), "hooks", "log", nil, nil, nil)
	f.mustExec(t, "UPDATE pc.notification_channels SET state = 'DISABLED' WHERE name = 'hooks'")
	f.mustExec(t, insert, f.org, m5ID(), "hooks", "log", nil, nil, nil) // a deleted channel frees its name
	f.want(t, m5Check, "paused without a reason", "UPDATE pc.notification_channels SET state = 'PAUSED' WHERE name = 'chat'")

	for _, col := range []string{"secret", "prev_secret"} {
		var ok bool
		d.AdminQueryRow(t, "SELECT has_column_privilege('pc_audit_ro', 'pc.notification_channels', $1, 'SELECT')",
			[]any{col}, &ok)
		if ok {
			t.Errorf("pc_audit_ro can read notification_channels.%s", col)
		}
	}
}

func TestHR159_DeliveriesAreBoundedAndTyped(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	channel, note := m5ID(), m5ID()
	f.mustExec(t, `INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, created_by)
		VALUES ($1, $2, 'ops', 'log', '{channel.test}', 'test')`, f.org, channel)
	f.mustExec(t, `INSERT INTO pc.notifications (org_id, id, type, severity, title, body, expires_at)
		VALUES ($1, $2, 'channel.test', 'INFO', 'Test', '', now() + interval '1 day')`, f.org, note)
	const insert = `INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, recipient_user_id, kind)
		VALUES ($1, $2, $3, $4, $5, $6)`
	delivery := m5ID()
	f.mustExec(t, insert, f.org, delivery, note, channel, nil, "log")
	f.mustExec(t, insert, f.org, m5ID(), note, nil, f.user, "email") // a personal email
	f.want(t, m5Check, "a Slack delivery without a channel", insert, f.org, m5ID(), note, nil, nil, "slack")
	f.want(t, m5Check, "an email without a recipient", insert, f.org, m5ID(), note, channel, nil, "email")
	f.want(t, m5Check, "a ninth attempt", "UPDATE pc.deliveries SET attempts = 9 WHERE id = $1", delivery)
	f.want(t, m5Check, "finished but still pending", "UPDATE pc.deliveries SET finished_at = now() WHERE id = $1", delivery)
	f.want(t, m5Check, "an error that is not a code",
		"UPDATE pc.deliveries SET last_error = 'connection refused: 10.0.0.1' WHERE id = $1", delivery)
	f.want(t, m5Denied, "a notification cannot be rewritten", "UPDATE pc.notifications SET title = 'Approve now' WHERE id = $1", note)
	f.want(t, m5Check, "a link to another site",
		`INSERT INTO pc.notifications (org_id, id, type, severity, title, body, link_path, expires_at)
		VALUES ($1, $2, 'channel.test', 'INFO', 'Test', '', '//evil.example/approve', now() + interval '1 day')`, f.org, m5ID())
	if err := f.exec("DELETE FROM pc.notifications WHERE id = $1", note); m5State(err) != "23503" || !strings.Contains(err.Error(), "deliveries") {
		t.Errorf("deleting a notification with deliveries: %v, want a foreign-key error (deliveries are deleted first)", err)
	}
}
