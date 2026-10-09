// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M6 (G0 M6):
// the application enforces the same rules first. Names are prefixed m6 so
// that they never collide with other milestones' schema tests in this
// package.

type m6Fixture struct {
	m5Fixture
	gateway, cert, brokerKey, connection string
}

const (
	m6Cert = `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, previous_id,
		not_before, not_after) VALUES ($1, $2, $3, $4, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $5, $6, now(), now() + $7::interval)`
	m6BrokerKey = `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, $4, $5, 'sha256:' || encode(sha256($5), 'hex'), $6)`
	m6Connection = `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode,
		created_by, updated_by) VALUES ($1, $2, $3, $4, $5, 'pc.mock-payments', $6, $7, 'test', 'test')`
	m6Credential = `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts,
		header, created_by) VALUES ($1, $2, $3, $4, $5, $6, '{api.example.com}', 'Authorization', 'test')`
)

func m6Bytes(n int, b byte) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// newM6Fixture extends the M5 fixture (org, user, WebAuthn credential) with
// one gateway, its certificate, an active broker key and one connection.
func newM6Fixture(t *testing.T, p *db.Pool) m6Fixture {
	t.Helper()
	f := m6Fixture{m5Fixture: newM5Fixture(t, p), gateway: m5ID(), cert: m5ID(), brokerKey: m5ID(), connection: m5ID()}
	f.mustExec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1)", f.org)
	f.mustExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.org, f.gateway)
	f.mustExec(t, m6Cert, f.org, f.cert, f.gateway, []byte{1}, "ENROLL", nil, "24 hours")
	f.mustExec(t, m6BrokerKey, f.org, f.brokerKey, f.gateway, 1, m6Bytes(1216, 1), f.cert)
	f.mustExec(t, m6Connection, f.org, f.connection, "payments", "http", f.gateway, "https://api.example.com", "pantherclaw_held")
	return f
}

func TestHR180_GatewayEnrollmentTokensAreSingleUseAndShortInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM6Fixture(t, d.AppPool(t))
	const insert = `INSERT INTO pc.gateway_enrollment_tokens (org_id, id, gateway_id, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, 'test', now() + $5::interval)`
	f.mustExec(t, insert, f.org, m5ID(), f.gateway, m5Secret(1), "15 minutes")
	f.want(t, m5Check, "a token valid longer than 15 minutes", insert, f.org, m5ID(), f.gateway, m5Secret(2), "16 minutes")
	f.want(t, m5Check, "a token that is not a SHA-256", insert, f.org, m5ID(), f.gateway, []byte("pcg_plain"), "15 minutes")
	f.want(t, m5Unique, "one token hash twice", insert, f.org, m5ID(), f.gateway, m5Secret(1), "15 minutes")
	f.want(t, m5Check, "used without the certificate it produced",
		"UPDATE pc.gateway_enrollment_tokens SET used_at = now() WHERE gateway_id = $1", f.gateway)
	f.want(t, m5Denied, "a token's gateway cannot change",
		"UPDATE pc.gateway_enrollment_tokens SET gateway_id = gateway_id WHERE gateway_id = $1", f.gateway)
	f.want(t, m5Denied, "a token's expiry cannot be extended",
		"UPDATE pc.gateway_enrollment_tokens SET expires_at = expires_at WHERE gateway_id = $1", f.gateway)

	var canSee, canSeeHash bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.gateway_enrollment_tokens', 'expires_at', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.gateway_enrollment_tokens', 'token_hash', 'SELECT')`, nil, &canSee, &canSeeHash)
	if !canSee || canSeeHash {
		t.Fatalf("pc_audit_ro: expires_at=%v token_hash=%v, want true, false", canSee, canSeeHash)
	}
}

func TestHR181_GatewayCertificatesAreShortLivedAndRevocableInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM6Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "a certificate valid longer than 25 hours", m6Cert, f.org, m5ID(), f.gateway, []byte{2}, "ENROLL", nil, "26 hours")
	f.want(t, m5Check, "a renewal without the certificate it renews", m6Cert, f.org, m5ID(), f.gateway, []byte{3}, "RENEW", nil, "24 hours")
	f.want(t, m5Unique, "one serial twice", m6Cert, f.org, m5ID(), f.gateway, []byte{1}, "ENROLL", nil, "24 hours")
	f.mustExec(t, m6Cert, f.org, m5ID(), f.gateway, []byte{4}, "RENEW", f.cert, "24 hours")
	f.want(t, m5Check, "revoked without a reason", "UPDATE pc.gateway_certs SET state = 'REVOKED', revoked_at = now() WHERE id = $1", f.cert)
	f.want(t, m5Check, "superseded without a time", "UPDATE pc.gateway_certs SET state = 'SUPERSEDED' WHERE id = $1", f.cert)
	f.want(t, m5Denied, "a certificate's key cannot change", "UPDATE pc.gateway_certs SET key_thumbprint = key_thumbprint WHERE id = $1", f.cert)
	f.want(t, m5Denied, "a certificate's validity cannot change", "UPDATE pc.gateway_certs SET not_after = not_after WHERE id = $1", f.cert)
	f.want(t, m5Denied, "a certificate's gateway cannot change", "UPDATE pc.gateway_certs SET gateway_id = gateway_id WHERE id = $1", f.cert)
	f.mustExec(t, "UPDATE pc.gateway_certs SET state = 'REVOKED', revoked_at = now(), revoke_reason = 'gateway_revoked' WHERE id = $1", f.cert)

	f.want(t, m5Check, "a revoked gateway without a time", "UPDATE pc.gateways SET state = 'REVOKED' WHERE id = $1", f.gateway)
	f.want(t, m5Denied, "a gateway's name cannot change", "UPDATE pc.gateways SET name = name WHERE id = $1", f.gateway)
}

func TestHR182_BrokerKeysAndSealedCredentialsInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM6Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "a broker key that is not an X-Wing public key", m6BrokerKey, f.org, m5ID(), f.gateway, 2, m6Bytes(32, 2), f.cert)
	f.want(t, m5Unique, "two active broker keys for one gateway", m6BrokerKey, f.org, m5ID(), f.gateway, 2, m6Bytes(1216, 3), f.cert)
	f.want(t, m5Denied, "a broker key cannot change", "UPDATE pc.broker_keys SET public_key = public_key WHERE id = $1", f.brokerKey)
	f.want(t, m5Denied, "the registering certificate cannot change", "UPDATE pc.broker_keys SET cert_id = cert_id WHERE id = $1", f.brokerKey)

	f.mustExec(t, m6Credential, f.org, m5ID(), f.connection, 1, f.brokerKey, m6Bytes(1200, 7))
	f.want(t, m5Unique, "two active credentials for one connection", m6Credential, f.org, m5ID(), f.connection, 2, f.brokerKey, m6Bytes(1200, 8))
	f.want(t, m5Check, "sealed bytes too short to hold an X-Wing encapsulation",
		m6Credential, f.org, m5ID(), f.connection, 3, f.brokerKey, m6Bytes(64, 9))
	f.want(t, m5Denied, "sealed bytes cannot be replaced in place", "UPDATE pc.credentials SET sealed = sealed WHERE connection_id = $1", f.connection)
	f.want(t, m5Denied, "a credential cannot move to another connection",
		"UPDATE pc.credentials SET connection_id = connection_id WHERE connection_id = $1", f.connection)
	f.want(t, m5Denied, "a credential's hosts cannot change", "UPDATE pc.credentials SET allowed_hosts = allowed_hosts WHERE connection_id = $1", f.connection)

	// The audit role sees credential metadata but never the sealed bytes (HR-061).
	var canSee, canSeeSealed bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.credentials', 'version', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.credentials', 'sealed', 'SELECT')`, nil, &canSee, &canSeeSealed)
	if !canSee || canSeeSealed {
		t.Fatalf("pc_audit_ro: version=%v sealed=%v, want true, false", canSee, canSeeSealed)
	}
}

func TestHR183_ConnectionsAreShapedAndModesClosedInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM6Fixture(t, d.AppPool(t))
	f.want(t, m5Unique, "two live connections with one name",
		m6Connection, f.org, m5ID(), "payments", "http", f.gateway, "https://api.example.com", "pantherclaw_held")
	f.want(t, m5Check, "a local connection with a base URL",
		m6Connection, f.org, m5ID(), "shell", "local", f.gateway, "https://api.example.com", "none")
	f.want(t, m5Check, "a local connection holding credentials", m6Connection, f.org, m5ID(), "shell", "local", f.gateway, nil, "agent_held")
	f.want(t, m5Check, "an http connection without a base URL", m6Connection, f.org, m5ID(), "api", "http", f.gateway, nil, "agent_held")
	f.want(t, m5Check, "a base URL that is not http(s)", m6Connection, f.org, m5ID(), "api", "http", f.gateway, "ftp://x.example", "agent_held")
	f.mustExec(t, m6Connection, f.org, m5ID(), "shell", "local", f.gateway, nil, "none")
	f.want(t, m5Check, "quarantined without a reason", "UPDATE pc.connections SET state = 'QUARANTINED' WHERE id = $1", f.connection)
	f.want(t, m5Denied, "a connection's kind cannot change", "UPDATE pc.connections SET kind = kind WHERE id = $1", f.connection)
	f.want(t, m5Denied, "a connection's name cannot change", "UPDATE pc.connections SET name = name WHERE id = $1", f.connection)

	const route = `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by) VALUES ($1, $2, $3, $4, 'test')`
	f.mustExec(t, route, f.org, f.connection, "payments-refund", "enforce")
	f.want(t, m5Check, "a mode other than monitor or enforce", route, f.org, f.connection, "payments-refund-get", "off")
	f.want(t, m5Check, "a route that is not a route id", route, f.org, f.connection, "../x", "enforce")

	const txn = `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, mode, connection_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK', 'gw', $6, $7)`
	f.mustExec(t, txn, f.org, m5ID(), m5ID(), m5ID(), m5Secret(1), "monitor", f.connection)
	f.want(t, m5Check, "a transaction in neither mode", txn, f.org, m5ID(), m5ID(), m5ID(), m5Secret(1), "observe", f.connection)
}

func TestHR113_KillSwitchRestoreNeedsTwoPeopleAndTwoKeysInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM6Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "engaged without who", "UPDATE pc.org_containment SET kill_switch = true WHERE org_id = $1", f.org)
	f.mustExec(t, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'alice', engaged_at = now(),
		engage_reason = 'incident' WHERE org_id = $1`, f.org)

	bob, bobCred := m5ID(), m5ID()
	f.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", f.org, bob)
	f.mustExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, bobCred, bob, m5Secret(9)[:16], m5Secret(2))

	const propose = `INSERT INTO pc.kill_switch_requests (org_id, id, epoch, proposed_by, proposer_cred, reason, expires_at)
		VALUES ($1, $2, 2, $3, $4, 'all clear', now() + $5::interval)`
	req := m5ID()
	f.want(t, m5Check, "a proposal valid longer than 30 minutes", propose, f.org, m5ID(), f.user, f.cred, "31 minutes")
	f.mustExec(t, propose, f.org, req, f.user, f.cred, "30 minutes")
	f.want(t, m5Unique, "two pending proposals", propose, f.org, m5ID(), bob, bobCred, "30 minutes")
	const confirm = `UPDATE pc.kill_switch_requests SET state = 'CONFIRMED', decided_by = $2, decider_cred = $3, decided_at = now()
		WHERE id = $1`
	f.want(t, m5Check, "confirmed by the proposer", confirm, req, f.user, bobCred)
	f.want(t, m5Check, "confirmed with the proposer's key", confirm, req, bob, f.cred)
	f.want(t, m5Check, "confirmed without a decider", "UPDATE pc.kill_switch_requests SET state = 'CONFIRMED', decided_at = now() WHERE id = $1", req)
	f.want(t, m5Denied, "the proposer cannot change", "UPDATE pc.kill_switch_requests SET proposed_by = proposed_by WHERE id = $1", req)
	f.mustExec(t, confirm, req, bob, bobCred)
}

// TestHR010_ContainmentChangesNotifyWatchers checks the server half of the
// containment stream: every epoch, kill-switch or gateway configuration
// change, whichever use case makes it, wakes LISTEN pc_containment with the
// org id and nothing else (HR-056).
func TestHR010_ContainmentChangesNotifyWatchers(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := newM6Fixture(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := p.Pgx().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN pc_containment"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "UNLISTEN *") }()

	for _, change := range []string{
		"UPDATE pc.org_containment SET epoch = epoch + 1 WHERE org_id = $1",
		"UPDATE pc.gateways SET config_version = config_version + 1 WHERE org_id = $1",
		`UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'alice', engaged_at = now(),
			engage_reason = 'x' WHERE org_id = $1`,
	} {
		f.mustExec(t, change, f.org)
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("%s: %v", change, err)
		}
		if n.Channel != "pc_containment" || n.Payload != f.org.String() {
			t.Fatalf("%s: notification %q %q, want pc_containment and the org id only", change, n.Channel, n.Payload)
		}
	}
	// Other columns of the containment row wake nobody.
	f.mustExec(t, "UPDATE pc.org_containment SET updated_at = now() WHERE org_id = $1", f.org)
	quiet, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	defer stop()
	if n, err := conn.Conn().WaitForNotification(quiet); err == nil {
		t.Fatalf("unexpected notification %+v", n)
	}
}
