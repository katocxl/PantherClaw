// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type env struct {
	d      *dbtest.DB
	pool   *db.Pool
	tokens *token.Service
	authn  *authnapp.Authenticator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	reg := keys.NewRegistry()
	for _, purpose := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(purpose)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := token.New(reg, "https://pc.example.test", token.Audience)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authnapp.NewAuthenticator(p, tokens, credential.EnvTest, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{d: d, pool: p, tokens: tokens, authn: a}
}

func (e *env) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// world is one org with an admin user and its CLI session, and a service
// account with a key and an API key.
type world struct {
	org             ids.OrgID
	user, session   ids.UUID
	sa, saKey, akID ids.UUID
	apiKey          credential.Token
}

func (e *env) world(t *testing.T, name string) world {
	t.Helper()
	w := world{org: ids.New[ids.Org](), user: ids.NewV7(), session: ids.NewV7(), sa: ids.NewV7(), saKey: ids.NewV7(), akID: ids.NewV7()}
	e.exec(t, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", w.org, name)
	e.exec(t, w.org, `INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', $3, $3)`,
		w.org, w.user, name+"-admin@example.test")
	e.exec(t, w.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`, w.org, ids.NewV7(), w.user)
	e.exec(t, w.org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, w.org, w.session, w.user, ids.NewV7().String()[:32])
	e.exec(t, w.org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", w.org, w.sa)
	e.exec(t, w.org, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by)
		VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`, w.org, ids.NewV7(), w.sa)
	e.exec(t, w.org, `INSERT INTO pc.service_account_keys (org_id, id, service_account_id, kid, alg, public_jwk, created_by, expires_at)
		VALUES ($1, $2, $3, repeat('k', 43), 'EdDSA', '{}', 'test', now() + interval '90 days')`, w.org, w.saKey, w.sa)
	var err error
	if w.apiKey, err = credential.New(credential.APIKey, credential.EnvTest, w.org); err != nil {
		t.Fatal(err)
	}
	e.exec(t, w.org, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
		VALUES ($1, $2, $3, 'deploy', $4, $5, ARRAY['team.read'], 'test', now() + interval '90 days')`,
		w.org, w.akID, w.sa, w.apiKey.Hash(), w.apiKey.Hint())
	return w
}

func (e *env) userToken(t *testing.T, org ids.OrgID, user, session ids.UUID) string {
	t.Helper()
	tok, _, err := e.tokens.Issue(token.Grant{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Session: session, ClientID: "pclaw",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) saToken(t *testing.T, w world) string {
	t.Helper()
	tok, _, err := e.tokens.Issue(token.Grant{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: w.sa}, Session: w.saKey, ClientID: "pcsa_x",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) rejected(t *testing.T, what, bearer string) {
	t.Helper()
	if _, err := e.authn.Authenticate(context.Background(), bearer); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("%s: err = %v, want ErrUnauthenticated", what, err)
	}
}

func TestIntAuthenticateAccessTokensAndAPIKeys(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "acme")
	c, err := e.authn.Authenticate(context.Background(), e.userToken(t, w.org, w.user, w.session))
	if err != nil {
		t.Fatal(err)
	}
	if c.Org != w.org || c.Principal.ID != w.user || c.Credential != tapp.CredAccessToken || !c.CanAnywhere(td.PermRoleBind) {
		t.Fatalf("user caller = %+v", c)
	}
	c, err = e.authn.Authenticate(context.Background(), e.saToken(t, w))
	if err != nil || c.Principal.Kind != td.KindServiceAccount || !c.CanAnywhere(td.PermRoleBind) {
		t.Fatalf("service-account caller = %+v (%v)", c, err)
	}
	c, err = e.authn.Authenticate(context.Background(), w.apiKey.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	if c.Credential != tapp.CredAPIKey || c.Principal.ID != w.sa || !c.CanAnywhere(td.PermTeamRead) || c.CanAnywhere(td.PermRoleBind) {
		t.Fatalf("API key caller = %+v: scopes must narrow the account's Org Admin role", c)
	}
	var touched bool
	err = e.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT last_used_at IS NOT NULL FROM pc.api_keys WHERE id = $1", w.akID).Scan(&touched)
	})
	if err != nil || !touched {
		t.Fatalf("last_used_at not recorded (%v)", err)
	}
}

// TestT032_RevocationTakesEffectOnTheNextRequest: a valid, unexpired token
// stops working as soon as its user, session, key, account or org is
// disabled, revoked or expired.
func TestT032_RevocationTakesEffectOnTheNextRequest(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		sql    string
		bearer func(*env, world) string
	}{
		"user disabled":         {"UPDATE pc.users SET state = 'DISABLED' WHERE id = $1", nil},
		"session revoked":       {"UPDATE pc.cli_sessions SET state = 'REVOKED' WHERE user_id = $1", nil},
		"session expired":       {"UPDATE pc.cli_sessions SET expires_at = now() - interval '1 second' WHERE user_id = $1", nil},
		"org suspended":         {"UPDATE pc.orgs SET state = 'SUSPENDED' WHERE id = (SELECT org_id FROM pc.users WHERE id = $1)", nil},
		"account disabled":      {"UPDATE pc.service_accounts SET state = 'DISABLED' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", saBearer},
		"account key revoked":   {"UPDATE pc.service_account_keys SET state = 'REVOKED' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", saBearer},
		"account key expired":   {"UPDATE pc.service_account_keys SET expires_at = now() - interval '1 second' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", saBearer},
		"API key revoked":       {"UPDATE pc.api_keys SET state = 'REVOKED' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", keyBearer},
		"API key expired":       {"UPDATE pc.api_keys SET expires_at = now() - interval '1 second' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", keyBearer},
		"API key's SA disabled": {"UPDATE pc.service_accounts SET state = 'DISABLED' WHERE org_id = (SELECT org_id FROM pc.users WHERE id = $1)", keyBearer},
	} {
		w := e.world(t, strings.ReplaceAll(name, " ", "-"))
		bearer := e.userToken(t, w.org, w.user, w.session)
		if tc.bearer != nil {
			bearer = tc.bearer(e, w)
		}
		if _, err := e.authn.Authenticate(context.Background(), bearer); err != nil {
			t.Fatalf("%s: works before the change: %v", name, err)
		}
		e.d.AdminExec(t, tc.sql, w.user) // as the owner: pc_app may not change expiry columns
		e.rejected(t, name, bearer)
	}
}

var (
	saBearer  = func(e *env, w world) string { return e.saTokenNoT(w) }
	keyBearer = func(_ *env, w world) string { return w.apiKey.Reveal() }
)

func (e *env) saTokenNoT(w world) string {
	tok, _, _ := e.tokens.Issue(token.Grant{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: w.sa}, Session: w.saKey, ClientID: "pcsa_x",
	}, time.Now())
	return tok
}

// TestT032_CredentialsCannotCrossOrgs: a validly signed token naming org B
// with org A's user and session, an API key re-addressed to another org, and
// keys of another environment are rejected.
func TestT032_CredentialsCannotCrossOrgs(t *testing.T) {
	e := newEnv(t)
	a, b := e.world(t, "a"), e.world(t, "b")
	e.rejected(t, "org B claim with A's user and session", e.userToken(t, b.org, a.user, a.session))
	e.rejected(t, "A's user with B's session", e.userToken(t, a.org, a.user, b.session))
	readdressed := strings.Replace(a.apiKey.Reveal(), hexOrg(a.org), hexOrg(b.org), 1)
	e.rejected(t, "API key re-addressed to org B", readdressed)
	liveKey := strings.Replace(a.apiKey.Reveal(), "pck_test_", "pck_live_", 1)
	e.rejected(t, "API key of another environment", liveKey)
	e.rejected(t, "empty", "")
	e.rejected(t, "garbage", "pck_test_zz")
	e.rejected(t, "oversized", strings.Repeat("a", authnapp.MaxBearerLen+1))
}

func hexOrg(o ids.OrgID) string { return strings.ReplaceAll(o.String(), "-", "") }

func TestIntJanitorRemovesOnlyExpiredRows(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "janitor")
	for i, age := range []string{"-2 minutes", "+2 minutes"} {
		e.d.AdminExec(t, `INSERT INTO pc.auth_replay (org_id, issuer, jti, expires_at) VALUES ($1, 'sa:x', $2, now() + $3::interval)`,
			w.org, "jti-"+string(rune('a'+i)), age)
		e.d.AdminExec(t, `INSERT INTO pc.device_codes (org_id, id, code_hash, user_code, device_jkt, device_jwk, expires_at)
			VALUES ($1, $2, $3, $4, repeat('j', 43), '{}', now() + $5::interval)`,
			w.org, ids.NewV7(), []byte(strings.Repeat(string(rune('a'+i)), 32)), "BCDFGHJ"+string("KL"[i]), map[int]string{0: "-2 days", 1: "+5 minutes"}[i])
	}
	e.d.AdminExec(t, `UPDATE pc.cli_sessions SET state = 'REVOKED', revoked_at = now() - interval '31 days' WHERE org_id = $1`, w.org)
	c, err := authnapp.CleanOrg(context.Background(), e.pool, w.org)
	if err != nil {
		t.Fatal(err)
	}
	if c.Replay != 1 || c.DeviceCodes != 1 || c.Sessions != 1 {
		t.Fatalf("cleaned %+v, want one of each", c)
	}
	var left int
	err = e.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM pc.auth_replay) + (SELECT count(*) FROM pc.device_codes)").Scan(&left)
	})
	if err != nil || left != 2 {
		t.Fatalf("live rows left = %d (%v)", left, err)
	}
}
