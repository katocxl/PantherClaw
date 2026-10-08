// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func edJWK(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := jose.JSONWebKey{Key: pub}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIntServiceAccountsKeysAndAPIKeys(t *testing.T) {
	f := newFixture(t)
	s := app.NewServiceAccounts(f.pool, credential.EnvTest)
	org := f.org(t, "acme")
	ctx := adminOf(org)

	sa := must(s.Create(ctx, "deploy-bot", "CI deploys"))
	if !strings.HasPrefix(sa.ClientID, credential.ClientIDPrefix) || sa.State != td.Enabled {
		t.Fatalf("service account = %+v", sa)
	}
	gotOrg, gotSA, err := credential.ParseClientID[td.ServiceAccount](sa.ClientID)
	if err != nil || gotOrg != org || gotSA != sa.ID {
		t.Fatalf("client id %q does not round-trip: %v", sa.ClientID, err)
	}
	_, err = s.Create(ctx, "deploy-bot", "")
	wantCode(t, "duplicate name", err, pcerr.AlreadyExists, "NAME_TAKEN")

	jwk := edJWK(t)
	k := must(s.AddKey(ctx, sa.ID, assertion.EdDSA, jwk, 0))
	if k.Alg != assertion.EdDSA || len(k.KID) != 43 || k.ExpiresAt.Sub(k.CreatedAt).Round(time.Hour) != app.DefaultKeyTTL {
		t.Fatalf("key = %+v", k)
	}
	_, err = s.AddKey(ctx, sa.ID, assertion.EdDSA, jwk, 0)
	wantCode(t, "same key twice", err, pcerr.AlreadyExists, "KEY_EXISTS")
	_, err = s.AddKey(ctx, sa.ID, assertion.ES256, edJWK(t), 0)
	wantCode(t, "Ed25519 key pinned as ES256", err, pcerr.InvalidArgument, "INVALID_PUBLIC_KEY")
	_, err = s.AddKey(ctx, sa.ID, "HS256", edJWK(t), 0)
	wantCode(t, "HS256", err, pcerr.InvalidArgument, "INVALID_PUBLIC_KEY")
	_, err = s.AddKey(ctx, sa.ID, assertion.EdDSA, edJWK(t), 400*24*time.Hour)
	wantCode(t, "key ttl over a year", err, pcerr.InvalidArgument, "INVALID_TTL")
	must(s.RevokeKey(ctx, sa.ID, k.ID))
	_, err = s.RevokeKey(ctx, sa.ID, k.ID)
	wantCode(t, "revoke key twice", err, pcerr.FailedPrecondition, "KEY_REVOKED")
	if l := must(s.ListKeys(ctx, sa.ID, page.Request{Size: 10})); len(l.Items) != 1 || l.Items[0].State != app.CredentialRevoked {
		t.Fatalf("keys = %+v", l.Items)
	}

	ak, tok, err := s.CreateAPIKey(ctx, sa.ID, "ci", []td.Permission{td.PermTeamRead, td.PermEnvironmentRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := credential.Parse(credential.APIKey, tok.Reveal())
	if err != nil || parsed.Env() != credential.EnvTest || parsed.Org() != org || ak.Hint != tok.Hint() {
		t.Fatalf("API key %v: %v", tok, err)
	}
	for name, scopes := range map[string][]td.Permission{
		"human-only scope": {td.PermApprovalRespond},
		"unknown scope":    {"team.*"},
		"no scopes":        nil,
	} {
		if _, _, err := s.CreateAPIKey(ctx, sa.ID, "x", scopes, 0); pcerr.CodeOf(err) != pcerr.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, _, err = s.CreateAPIKey(ctx, sa.ID, "ci", []td.Permission{td.PermTeamRead}, 0)
	wantCode(t, "duplicate API key name", err, pcerr.AlreadyExists, "NAME_TAKEN")
	must(s.RevokeAPIKey(ctx, ak.ID))
	_, err = s.RevokeAPIKey(ctx, ak.ID)
	wantCode(t, "revoke API key twice", err, pcerr.FailedPrecondition, "API_KEY_REVOKED")

	must(s.SetState(ctx, sa.ID, td.Disabled))
	_, err = s.AddKey(ctx, sa.ID, assertion.EdDSA, edJWK(t), 0)
	wantCode(t, "key for disabled account", err, pcerr.FailedPrecondition, "PRINCIPAL_DISABLED")
	_, _, err = s.CreateAPIKey(ctx, sa.ID, "late", []td.Permission{td.PermTeamRead}, 0)
	wantCode(t, "API key for disabled account", err, pcerr.FailedPrecondition, "PRINCIPAL_DISABLED")

	viewer := as(org, orgRole(org, td.RoleViewer))
	_, err = s.Create(viewer, "nope", "")
	wantCode(t, "viewer creates service account", err, pcerr.PermissionDenied, "PERMISSION_DENIED")
	for name, n := range map[string]int{
		"access.service_account_created": 1, "access.service_account_key_added": 1, "access.service_account_key_revoked": 1,
		"access.api_key_created": 1, "access.api_key_revoked": 1, "access.service_account_disabled": 1,
	} {
		if got := f.auditCount(t, org, name); got != n {
			t.Errorf("audit %s = %d, want %d", name, got, n)
		}
	}
}

// TestT037_ServiceAccountIDOR: another org's service accounts, keys and API
// keys are NotFound.
func TestT037_ServiceAccountIDOR(t *testing.T) {
	f := newFixture(t)
	s := app.NewServiceAccounts(f.pool, credential.EnvTest)
	a, b := f.org(t, "a"), f.org(t, "b")
	ctxA, ctxB := adminOf(a), adminOf(b)
	sa := must(s.Create(ctxA, "bot", ""))
	k := must(s.AddKey(ctxA, sa.ID, assertion.EdDSA, edJWK(t), 0))
	ak, _, err := s.CreateAPIKey(ctxA, sa.ID, "ci", []td.Permission{td.PermTeamRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]error{}
	_, checks["get"] = s.Get(ctxB, sa.ID)
	_, checks["disable"] = s.SetState(ctxB, sa.ID, td.Disabled)
	_, checks["add key"] = s.AddKey(ctxB, sa.ID, assertion.EdDSA, edJWK(t), 0)
	_, checks["list keys"] = s.ListKeys(ctxB, sa.ID, page.Request{Size: 10})
	_, checks["revoke key"] = s.RevokeKey(ctxB, sa.ID, k.ID)
	_, _, checks["create API key"] = s.CreateAPIKey(ctxB, sa.ID, "x", []td.Permission{td.PermTeamRead}, 0)
	_, checks["revoke API key"] = s.RevokeAPIKey(ctxB, ak.ID)
	for name, err := range checks {
		wantCode(t, name, err, pcerr.NotFound, "")
	}
	if l := must(s.ListAPIKeys(ctxB, ids.ID[td.ServiceAccount]{}, page.Request{Size: 10})); len(l.Items) != 0 {
		t.Fatalf("B lists A's API keys: %+v", l.Items)
	}
}

// TestIntCredentialIssuanceCannotEscalate: a Security Admin
// (service_account.manage, no role.bind) cannot mint a key or an API key
// that would let it act with permissions it lacks, such as an Org Admin
// account's role.bind; it can for accounts and scopes within its own
// permissions. An Org Admin (role.bind) can always issue.
func TestIntCredentialIssuanceCannotEscalate(t *testing.T) {
	f := newFixture(t)
	s := app.NewServiceAccounts(f.pool, credential.EnvTest)
	a := app.NewAccess(f.pool, nil)
	org := f.org(t, "acme")
	admin := adminOf(org)
	secAdmin := as(org, orgRole(org, td.RoleSecurityAdmin))
	team := must(f.h.CreateTeam(admin, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "t", Name: "T"}))
	account := func(name string, role td.RoleName, scope td.Scope) td.ServiceAccountID {
		sa := must(s.Create(admin, name, ""))
		must2(a.CreateRoleBinding(admin, role, td.PrincipalRef{Kind: td.KindServiceAccount, ID: sa.ID.UUID()}, scope))
		return sa.ID
	}
	privileged := account("privileged", td.RoleOrgAdmin, orgScope(org))
	viewer := account("viewer", td.RoleViewer, td.Scope{Type: td.ScopeTeam, ID: team.ID.UUID()})
	owner := account("owner", td.RoleAgentOwner, td.Scope{Type: td.ScopeTeam, ID: team.ID.UUID()})

	_, _, err := s.CreateAPIKey(secAdmin, privileged, "escalate", []td.Permission{td.PermRoleBind}, 0)
	wantCode(t, "API key with role.bind", err, pcerr.PermissionDenied, "PRIVILEGE_ESCALATION")
	_, err = s.AddKey(secAdmin, privileged, assertion.EdDSA, edJWK(t), 0)
	wantCode(t, "key for an Org Admin account", err, pcerr.PermissionDenied, "PRIVILEGE_ESCALATION")
	_, err = s.AddKey(secAdmin, owner, assertion.EdDSA, edJWK(t), 0)
	wantCode(t, "key carrying agent.manage", err, pcerr.PermissionDenied, "PRIVILEGE_ESCALATION")

	if _, _, err := s.CreateAPIKey(secAdmin, privileged, "reader", []td.Permission{td.PermUserRead}, 0); err != nil {
		t.Errorf("API key limited to a permission the caller holds: %v", err)
	}
	if _, _, err := s.CreateAPIKey(secAdmin, owner, "agents", []td.Permission{td.PermAgentRead}, 0); err != nil {
		t.Errorf("API key limited to agent.read: %v", err)
	}
	if _, err := s.AddKey(secAdmin, viewer, assertion.EdDSA, edJWK(t), 0); err != nil {
		t.Errorf("key for a team viewer account: %v", err)
	}
	if _, err := s.AddKey(admin, privileged, assertion.EdDSA, edJWK(t), 0); err != nil {
		t.Errorf("Org Admin issuing a key: %v", err)
	}
	if _, _, err := s.CreateAPIKey(admin, owner, "full", []td.Permission{td.PermAgentManage}, 0); err != nil {
		t.Errorf("Org Admin issuing an API key: %v", err)
	}
}
