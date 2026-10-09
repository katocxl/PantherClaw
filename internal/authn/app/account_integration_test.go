// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// as returns ctx carrying a caller of org with one org-scope role.
func as(org ids.OrgID, kind td.PrincipalKind, id ids.UUID, role td.RoleName) context.Context {
	var bs []td.Binding
	if role != "" {
		bs = []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs},
		Credential: tapp.CredAccessToken,
	})
}

func TestT043_AdminsSignPeopleOutAndRemoveKeysButCannotActAsThem(t *testing.T) {
	e := newWAEnv(t)
	acct := authnapp.NewAccount(e.pool, e.wa)
	s, _ := e.session(t, true)
	key, err := e.register(t, s, e.authenticator(t, webauthntest.ES256), "Desk key")
	if err != nil {
		t.Fatal(err)
	}
	cli := ids.NewV7()
	e.exec(t, e.org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, device_name, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', 'laptop', $4, now() + interval '8 hours')`, e.org, cli, e.user, sum32(7))

	admin := ids.NewV7()
	e.exec(t, e.org, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'admin')`, e.org, admin)
	viewer := as(e.org, td.KindUser, ids.NewV7(), td.RoleViewer)
	adminCtx := as(e.org, td.KindUser, admin, td.RoleOrgAdmin)

	// Reading and changing another person's sessions needs user.read and
	// user.manage at org scope.
	if _, err := acct.ListUserSessions(viewer, e.user); err == nil {
		t.Fatalf("viewer listed sessions: %v", err)
	}
	if _, err := acct.RevokeUserSessions(viewer, e.user); err == nil {
		t.Fatal("viewer revoked sessions")
	}
	list, err := acct.ListUserSessions(adminCtx, e.user)
	if err != nil || len(list) != 2 {
		t.Fatalf("admin list: %d %v", len(list), err)
	}
	keys, err := acct.ListUserKeys(adminCtx, e.user)
	if err != nil || len(keys) != 1 || keys[0].ID != key.ID {
		t.Fatalf("admin keys: %+v %v", keys, err)
	}
	n, err := acct.RevokeUserSessions(adminCtx, e.user)
	if err != nil || n != 2 {
		t.Fatalf("revoke all: %d %v", n, err)
	}
	if got := e.notices.types(); got[len(got)-1] != "security.sessions_revoked" {
		t.Errorf("notices %v", got)
	}
	if c := e.count(t, "SELECT count(*) FROM pc.cli_sessions WHERE state = 'REVOKED' AND revoke_reason = 'ADMIN_REVOKED'"); c != 1 {
		t.Errorf("CLI session not revoked: %d", c)
	}
	if err := acct.RemoveUserKey(adminCtx, e.user, key.ID); err != nil {
		t.Fatal(err)
	}
	if c := e.count(t, "SELECT count(*) FROM pc.webauthn_credentials WHERE state = 'REMOVED' AND state_reason = 'ADMIN_REMOVED'"); c != 1 {
		t.Error("key not removed by the admin")
	}
	// The admin's own key list is empty: removing is not owning.
	if mine, err := acct.ListMyKeys(adminCtx); err != nil || len(mine) != 0 {
		t.Fatalf("admin's own keys %+v %v", mine, err)
	}
	// IDOR: another org's user, or a key of another user, is not found.
	other := ids.New[ids.Org]()
	if _, err := acct.ListUserSessions(adminCtx, ids.NewV7()); !errors.Is(err, tapp.ErrUserNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if err := acct.RemoveUserKey(adminCtx, admin, key.ID); !errors.Is(err, authnapp.ErrNoSuchKey) {
		t.Errorf("a key under the wrong user: %v", err)
	}
	if _, err := acct.ListUserSessions(as(other, td.KindUser, admin, td.RoleOrgAdmin), e.user); err == nil {
		t.Error("an admin of another org read the sessions")
	}
}

func TestHR156_SelfServiceIsForPeopleAndTheirOwnSessions(t *testing.T) {
	e := newWAEnv(t)
	acct := authnapp.NewAccount(e.pool, e.wa)
	mine := e.mustSignIn(t)
	cli := ids.NewV7()
	e.exec(t, e.org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, e.org, cli, e.user, sum32(8))
	ctx := as(e.org, td.KindUser, e.user, td.RoleViewer)
	list, err := acct.ListMySessions(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("own sessions: %d %v", len(list), err)
	}
	if err := acct.RevokeMySession(ctx, cli); err != nil {
		t.Fatal(err)
	}
	if err := acct.RevokeMySession(ctx, mine.Session); err != nil {
		t.Fatal(err)
	}
	if _, err := e.browser.Authenticate(context.Background(), mine.Secret); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Error("a revoked browser session still works")
	}
	if err := acct.RevokeMySession(ctx, ids.NewV7()); !errors.Is(err, authnapp.ErrNoSuchSession) {
		t.Errorf("unknown session: %v", err)
	}
	sa := as(e.org, td.KindServiceAccount, ids.NewV7(), td.RoleOrgAdmin)
	if _, err := acct.ListMySessions(sa); !errors.Is(err, authnapp.ErrUsersOnly) {
		t.Errorf("service account: %v", err)
	}
	if _, err := acct.ListMyKeys(sa); !errors.Is(err, authnapp.ErrUsersOnly) {
		t.Errorf("service account keys: %v", err)
	}
}
