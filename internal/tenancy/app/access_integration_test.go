// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// asUser returns ctx for an existing user with the given bindings.
func asUser(org ids.OrgID, u td.UserID, bs ...td.Binding) context.Context {
	return app.WithCaller(context.Background(), app.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: u.UUID()}, Bindings: bs},
		Credential: app.CredAccessToken,
	})
}

func userRef(u td.UserID) td.PrincipalRef { return td.PrincipalRef{Kind: td.KindUser, ID: u.UUID()} }

func orgScope(org ids.OrgID) td.Scope { return td.Scope{Type: td.ScopeOrg, ID: org.UUID()} }

// serviceAccount inserts an active service account.
func (f *fixture) serviceAccount(t *testing.T, org ids.OrgID, name string) td.ServiceAccountID {
	t.Helper()
	id := ids.New[td.ServiceAccount]()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, $3, 'test')", org, id, name)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// admin creates an active user holding Org Admin (stored binding) and
// returns it with its context.
func (f *fixture) admin(t *testing.T, a *app.Access, boot context.Context, org ids.OrgID, email string) (td.UserID, context.Context) {
	t.Helper()
	u := f.user(t, org, email)
	must2(a.CreateRoleBinding(boot, td.RoleOrgAdmin, userRef(u), orgScope(org)))
	return u, asUser(org, u, orgRole(org, td.RoleOrgAdmin))
}

func TestIntInvitations(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	ctx := adminOf(org)

	inv, tok, err := a.CreateInvitation(ctx, " Bob@Example.TEST ", []td.RoleName{td.RoleApprover, td.RoleViewer}, 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := credential.Parse(credential.Invitation, tok.Reveal())
	if err != nil || parsed.Org() != org {
		t.Fatalf("token %v: %v", tok, err)
	}
	if inv.Email != "bob@example.test" || inv.State != app.InvitationPending || inv.Bootstrap ||
		inv.ExpiresAt.Sub(inv.CreatedAt).Round(time.Hour) != app.DefaultInvitationTTL {
		t.Fatalf("invitation = %+v", inv)
	}
	var stored []byte
	err = f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT token_hash FROM pc.invitations WHERE id = $1", inv.ID).Scan(&stored)
	})
	if err != nil || string(stored) != string(tok.Hash()) || strings.Contains(string(stored), tok.Reveal()) {
		t.Fatal("invitation token is not stored as its hash only")
	}

	for name, roles := range map[string][]td.RoleName{
		"unknown role": {"root"}, "duplicate roles": {td.RoleViewer, td.RoleViewer},
	} {
		if _, _, err := a.CreateInvitation(ctx, "c@example.test", roles, 0); pcerr.CodeOf(err) != pcerr.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, _, err = a.CreateInvitation(ctx, "c@example.test", nil, 31*24*time.Hour)
	wantCode(t, "ttl too long", err, pcerr.InvalidArgument, "INVALID_TTL")
	_, _, err = a.CreateInvitation(as(org, orgRole(org, td.RoleViewer)), "d@example.test", nil, 0)
	wantCode(t, "viewer invites", err, pcerr.PermissionDenied, "PERMISSION_DENIED")

	if l := must(a.ListInvitations(ctx, page.Request{Size: 10}, false)); len(l.Items) != 1 {
		t.Fatalf("pending = %+v", l.Items)
	}
	if r := must(a.RevokeInvitation(ctx, inv.ID)); r.State != app.InvitationRevoked {
		t.Fatalf("revoked = %+v", r)
	}
	_, err = a.RevokeInvitation(ctx, inv.ID)
	wantCode(t, "revoke twice", err, pcerr.FailedPrecondition, "INVITATION_CLOSED")
	_, err = a.RevokeInvitation(ctx, ids.New[td.Invitation]())
	wantCode(t, "unknown invitation", err, pcerr.NotFound, "INVITATION_NOT_FOUND")
	if l := must(a.ListInvitations(ctx, page.Request{Size: 10}, false)); len(l.Items) != 0 {
		t.Fatalf("revoked listed as pending: %+v", l.Items)
	}
	if l := must(a.ListInvitations(ctx, page.Request{Size: 10}, true)); len(l.Items) != 1 {
		t.Fatalf("include_closed = %+v", l.Items)
	}
	if n := f.auditCount(t, org, "access.invitation_created") + f.auditCount(t, org, "access.invitation_revoked"); n != 2 {
		t.Fatalf("invitation audit entries = %d", n)
	}
}

func TestIntRoleBindingRules(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	boot := adminOf(org)
	me, ctx := f.admin(t, a, boot, org, "admin@example.test")
	bob := f.user(t, org, "bob@example.test")
	sa := f.serviceAccount(t, org, "ci")
	tm := must(f.h.CreateTeam(ctx, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "t", Name: "T"}))
	teamScope := td.Scope{Type: td.ScopeTeam, ID: tm.ID.UUID()}

	b := must2(a.CreateRoleBinding(ctx, td.RoleViewer, userRef(bob), teamScope))
	if b.Scope != teamScope || b.Principal != userRef(bob) || b.CreatedBy != userRef(me).String() {
		t.Fatalf("binding = %+v", b)
	}
	_, _, err := a.CreateRoleBinding(ctx, td.RoleViewer, userRef(bob), teamScope)
	wantCode(t, "duplicate", err, pcerr.AlreadyExists, "ROLE_BINDING_EXISTS")
	saRef := td.PrincipalRef{Kind: td.KindServiceAccount, ID: sa.UUID()}
	_, _, err = a.CreateRoleBinding(ctx, td.RoleApprover, saRef, orgScope(org))
	wantCode(t, "approver for a service account", err, pcerr.FailedPrecondition, "HUMAN_ONLY_ROLE")
	must2(a.CreateRoleBinding(ctx, td.RoleAgentOwner, saRef, teamScope))
	_, _, err = a.CreateRoleBinding(ctx, td.RoleOrgAdmin, userRef(bob), teamScope)
	wantCode(t, "org admin at team scope", err, pcerr.InvalidArgument, "SCOPE_NOT_ALLOWED")
	_, _, err = a.CreateRoleBinding(ctx, td.RoleViewer, userRef(ids.New[td.User]()), orgScope(org))
	wantCode(t, "unknown user", err, pcerr.NotFound, "USER_NOT_FOUND")
	_, _, err = a.CreateRoleBinding(ctx, td.RoleViewer, userRef(bob), td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()})
	wantCode(t, "unknown team", err, pcerr.NotFound, "TEAM_NOT_FOUND")
	must(a.SetUserState(ctx, bob, td.Disabled))
	_, _, err = a.CreateRoleBinding(ctx, td.RoleResponder, userRef(bob), orgScope(org))
	wantCode(t, "disabled user", err, pcerr.FailedPrecondition, "PRINCIPAL_DISABLED")

	// Self-grant is allowed (ADR-0016), reported and audited.
	_, self, err := a.CreateRoleBinding(ctx, td.RoleApprover, userRef(me), orgScope(org))
	if err != nil || !self {
		t.Fatalf("self-grant: self=%v err=%v", self, err)
	}
	var selfAudits int
	err = f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries
			WHERE kind = 'audit.access.role_bound' AND convert_from(body, 'UTF8') LIKE '%"self_grant":"true"%'`).Scan(&selfAudits)
	})
	if err != nil || selfAudits != 1 {
		t.Fatalf("self-grant audit entries = %d (%v)", selfAudits, err)
	}

	// The interceptor's loader sees exactly the stored bindings.
	err = f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		bs, err := app.Bindings(ctx, dbqNew(tx), org, userRef(me))
		if err != nil {
			return err
		}
		s := td.Subject{Org: org, Principal: userRef(me), Bindings: bs}
		if !s.CanAnywhere(td.PermApprovalRespond) || !s.CanAnywhere(td.PermRoleBind) || len(bs) != 2 {
			t.Errorf("loaded bindings %+v", bs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	l := must(a.ListRoleBindings(ctx, page.Request{Size: 50}, &saRef))
	if len(l.Items) != 1 || l.Items[0].Role != td.RoleAgentOwner {
		t.Fatalf("bindings of the service account = %+v", l.Items)
	}
	if err := a.DeleteRoleBinding(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "delete twice", a.DeleteRoleBinding(ctx, b.ID), pcerr.NotFound, "ROLE_BINDING_NOT_FOUND")
}

func must2[T any](v T, _ bool, err error) T { return must(v, err) }

// TestIntLastOrgAdminIsProtected: the last active Org Admin can be neither
// unbound nor disabled, also when two admins race to remove each other.
func TestIntLastOrgAdminIsProtected(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	boot := adminOf(org)
	u1, ctx1 := f.admin(t, a, boot, org, "one@example.test")
	u2, ctx2 := f.admin(t, a, boot, org, "two@example.test")

	must(a.SetUserState(ctx1, u2, td.Disabled))
	_, err := a.SetUserState(ctx1, u1, td.Disabled)
	wantCode(t, "disable last admin", err, pcerr.FailedPrecondition, "LAST_ORG_ADMIN")
	bs := must(a.ListRoleBindings(ctx1, page.Request{Size: 50}, ptrRef(userRef(u1))))
	wantCode(t, "unbind last admin", a.DeleteRoleBinding(ctx1, bs.Items[0].ID), pcerr.FailedPrecondition, "LAST_ORG_ADMIN")
	must(a.SetUserState(ctx1, u2, td.Enabled))

	// Two admins disable each other at the same time: one must lose.
	for range 10 {
		var wg sync.WaitGroup
		var e1, e2 error
		wg.Add(2)
		go func() { defer wg.Done(); _, e1 = a.SetUserState(ctx1, u2, td.Disabled) }()
		go func() { defer wg.Done(); _, e2 = a.SetUserState(ctx2, u1, td.Disabled) }()
		wg.Wait()
		if e1 == nil && e2 == nil {
			t.Fatal("both admins disabled")
		}
		var active int
		err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc.users WHERE state = 'ACTIVE'").Scan(&active)
		})
		if err != nil || active != 1 {
			t.Fatalf("active admins = %d (%v)", active, err)
		}
		must(a.SetUserState(boot, u1, td.Enabled))
		must(a.SetUserState(boot, u2, td.Enabled))
	}
}

func ptrRef(p td.PrincipalRef) *td.PrincipalRef { return &p }

func TestIntDisablingAUserRevokesItsSessions(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	bob := f.user(t, org, "bob@example.test")
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
			VALUES ($1, $2, $3, repeat('a', 43), '{}', $4, now() + interval '8 hours')`, org, ids.NewV7(), bob, make([]byte, 32))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	must(a.SetUserState(adminOf(org), bob, td.Disabled))
	var state, reason string
	err = f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, revoke_reason FROM pc.cli_sessions WHERE user_id = $1", bob).Scan(&state, &reason)
	})
	if err != nil || state != "REVOKED" || reason != "USER_DISABLED" {
		t.Fatalf("session state %q reason %q (%v)", state, reason, err)
	}
}

// TestT037_AccessIDOR: another org's users, invitations, bindings and
// scopes are NotFound.
func TestT037_AccessIDOR(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	orgA, orgB := f.org(t, "a"), f.org(t, "b")
	ctxA, ctxB := adminOf(orgA), adminOf(orgB)
	alice := f.user(t, orgA, "alice@a.test")
	bobB := f.user(t, orgB, "bob@b.test")
	inv, _, err := a.CreateInvitation(ctxA, "x@a.test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := must2(a.CreateRoleBinding(ctxA, td.RoleViewer, userRef(alice), orgScope(orgA)))
	tm := must(f.h.CreateTeam(ctxA, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "t", Name: "T"}))

	checks := map[string]error{}
	_, checks["get user"] = a.GetUser(ctxB, alice)
	_, checks["disable user"] = a.SetUserState(ctxB, alice, td.Disabled)
	_, checks["revoke invitation"] = a.RevokeInvitation(ctxB, inv.ID)
	checks["delete binding"] = a.DeleteRoleBinding(ctxB, b.ID)
	_, _, checks["bind foreign user"] = a.CreateRoleBinding(ctxB, td.RoleViewer, userRef(alice), orgScope(orgB))
	_, _, checks["bind at foreign team"] = a.CreateRoleBinding(ctxB, td.RoleViewer, userRef(bobB), td.Scope{Type: td.ScopeTeam, ID: tm.ID.UUID()})
	_, _, checks["bind at foreign org"] = a.CreateRoleBinding(ctxB, td.RoleViewer, userRef(bobB), orgScope(orgA))
	for name, err := range checks {
		wantCode(t, name, err, pcerr.NotFound, "")
	}
	if l := must(a.ListUsers(ctxB, page.Request{Size: 50})); len(l.Items) != 1 || l.Items[0].ID != bobB {
		t.Fatalf("B lists users %+v", l.Items)
	}
	if got := must(a.GetUser(ctxA, alice)); got.State != td.Enabled {
		t.Fatal("A's user changed")
	}
}

func TestIntWhoAmI(t *testing.T) {
	f := newFixture(t)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	boot := adminOf(org)
	u, ctx := f.admin(t, a, boot, org, "me@example.test")
	id := must(a.WhoAmI(ctx))
	if id.OrgName != "acme" || id.DisplayName != "me@example.test" || len(id.Bindings) != 1 ||
		id.Bindings[0].Role != td.RoleOrgAdmin || id.Principal != userRef(u) {
		t.Fatalf("whoami = %+v", id)
	}
	if roles := must(a.ListRoles(ctx)); len(roles) != len(td.Roles()) {
		t.Fatalf("roles = %d", len(roles))
	}
}
