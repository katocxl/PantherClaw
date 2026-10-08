// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package tenancyrpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const issuer = "https://pc.example.test"

type business struct{}

func (business) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition = billing.Business
	return e, nil
}

type stack struct {
	pool   *db.Pool
	tokens *token.Service
	url    string
}

func newStack(t *testing.T) *stack {
	t.Helper()
	pool := dbtest.New(t).AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := token.New(reg, issuer, token.Audience)
	if err != nil {
		t.Fatal(err)
	}
	authn, err := authnapp.NewAuthenticator(pool, tokens, credential.EnvTest, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, p := range declared {
		perms[proc] = td.Permission(p)
	}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(authn, perms, nil)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterTenancyServiceHandler(s, tenancyrpc.NewTenancy(app.NewHierarchy(pool, business{})))
	pantherclawv1connect.RegisterAccessServiceHandler(s, tenancyrpc.NewAccess(app.NewAccess(pool, nil)))
	pantherclawv1connect.RegisterServiceAccountServiceHandler(s, tenancyrpc.NewServiceAccounts(app.NewServiceAccounts(pool, credential.EnvTest)))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	oauthhttp.New(authnapp.NewOAuth(pool, tokens, issuer, clock.System{}, nil), issuer, httpx.NewLimiter(1000, time.Minute, nil)).Mount(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &stack{pool: pool, tokens: tokens, url: ts.URL}
}

func (s *stack) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	err := s.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// login creates a user with a role at org scope and a CLI session, and
// returns a bearer token for it.
func (s *stack) login(t *testing.T, org ids.OrgID, email string, role td.RoleName) (ids.UUID, string) {
	t.Helper()
	user, session := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', $3, $3)", org, user, email)
	s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), user)
	s.exec(t, org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, org, session, user, user.String()[:32])
	tok, _, err := s.tokens.Issue(token.Grant{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Session: session, ClientID: "pclaw",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return user, tok
}

func (s *stack) org(t *testing.T, name string) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, name)
	return org
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.tok != "" {
		r.Header.Set("Authorization", "Bearer "+b.tok)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) clients(tok string) (pantherclawv1connect.TenancyServiceClient, pantherclawv1connect.AccessServiceClient) {
	tr := connecthttp.NewTransport(&http.Client{Transport: bearer{tok}}, s.url)
	return pantherclawv1connect.NewTenancyServiceClient(connect.NewClient(tr)), pantherclawv1connect.NewAccessServiceClient(connect.NewClient(tr))
}

func wantCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Errorf("%s: %v, want %s", what, err, want)
	}
}

func TestIntRPCTenancyAndAccess(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	orgA, orgB := s.org(t, "acme"), s.org(t, "other")
	adminID, adminTok := s.login(t, orgA, "admin@acme.test", td.RoleOrgAdmin)
	viewerID, viewerTok := s.login(t, orgA, "viewer@acme.test", td.RoleViewer)
	_, otherTok := s.login(t, orgB, "admin@other.test", td.RoleOrgAdmin)
	ten, acc := s.clients(adminTok)

	me, err := acc.WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{})
	if err != nil || me.GetOrgId() != orgA.String() || me.GetPrincipal().GetDisplayName() != "admin@acme.test" ||
		me.GetCredential() != "access_token" || !strings.Contains(strings.Join(me.GetPermissions(), " "), "role.bind") {
		t.Fatalf("WhoAmI = %v, %v", me, err)
	}
	if _, err := ten.UpdateOrg(ctx, &pantherclawv1.UpdateOrgRequest{Name: "Acme Corp"}); err != nil {
		t.Fatal(err)
	}
	bu, err := ten.CreateBusinessUnit(ctx, &pantherclawv1.CreateBusinessUnitRequest{Slug: "pay", Name: "Payments"})
	if err != nil {
		t.Fatal(err)
	}
	team, err := ten.CreateTeam(ctx, &pantherclawv1.CreateTeamRequest{
		BusinessUnitId: bu.GetBusinessUnit().GetId(), Slug: "refunds", Name: "Refunds", Description: "keep",
	})
	if err != nil {
		t.Fatal(err)
	}
	teamID := team.GetTeam().GetId()
	env, err := ten.CreateEnvironment(ctx, &pantherclawv1.CreateEnvironmentRequest{
		TeamId: teamID, Slug: "prod", Name: "Production", Kind: pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION,
	})
	if err != nil || env.GetEnvironment().GetKind() != pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION {
		t.Fatalf("CreateEnvironment = %v, %v", env, err)
	}
	newName := "Refunds EU"
	upd, err := ten.UpdateTeam(ctx, &pantherclawv1.UpdateTeamRequest{Id: teamID, Name: &newName})
	if err != nil || upd.GetTeam().GetName() != newName || upd.GetTeam().GetDescription() != "keep" {
		t.Fatalf("UpdateTeam = %v, %v", upd, err)
	}
	if _, err := ten.AddTeamMember(ctx, &pantherclawv1.AddTeamMemberRequest{TeamId: teamID, UserId: viewerID.String()}); err != nil {
		t.Fatal(err)
	}
	inv, err := acc.CreateInvitation(ctx, &pantherclawv1.CreateInvitationRequest{Email: "new@acme.test", Roles: []string{"viewer"}})
	if err != nil || !strings.HasPrefix(inv.GetToken(), "pci_") || inv.GetInvitation().GetState() != pantherclawv1.InvitationState_INVITATION_STATE_PENDING {
		t.Fatalf("CreateInvitation = %v, %v", inv, err)
	}
	b, err := acc.CreateRoleBinding(ctx, &pantherclawv1.CreateRoleBindingRequest{
		Role: "approver", PrincipalType: pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER, PrincipalId: adminID.String(),
		Scope: &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_TEAM, Id: teamID},
	})
	if err != nil || !b.GetSelfGrant() || b.GetBinding().GetScope().GetId() != teamID {
		t.Fatalf("self-grant = %v, %v", b, err)
	}
	roles, err := acc.ListRoles(ctx, &pantherclawv1.ListRolesRequest{})
	if err != nil || len(roles.GetRoles()) != 10 {
		t.Fatalf("ListRoles = %d, %v", len(roles.GetRoles()), err)
	}

	// Validation and id parsing happen before any use case.
	_, err = ten.CreateTeam(ctx, &pantherclawv1.CreateTeamRequest{Slug: "Bad Slug", Name: "x"})
	wantCode(t, "invalid slug", err, connect.CodeInvalidArgument)
	_, err = ten.GetTeam(ctx, &pantherclawv1.GetTeamRequest{Id: "4b0c8a0c-3f2b-4c1a-9d3e-2f1a0b9c8d7e"})
	wantCode(t, "UUIDv4 id", err, connect.CodeInvalidArgument)

	// A viewer reads but cannot change; the interceptor refuses early.
	vten, _ := s.clients(viewerTok)
	if _, err := vten.GetTeam(ctx, &pantherclawv1.GetTeamRequest{Id: teamID}); err != nil {
		t.Errorf("viewer GetTeam: %v", err)
	}
	_, err = vten.CreateTeam(ctx, &pantherclawv1.CreateTeamRequest{Slug: "x", Name: "x"})
	wantCode(t, "viewer CreateTeam", err, connect.CodePermissionDenied)

	// Another org's admin sees nothing of org A (IDOR).
	oten, oacc := s.clients(otherTok)
	_, err = oten.GetTeam(ctx, &pantherclawv1.GetTeamRequest{Id: teamID})
	wantCode(t, "other org GetTeam", err, connect.CodeNotFound)
	_, err = oten.ArchiveEnvironment(ctx, &pantherclawv1.ArchiveEnvironmentRequest{Id: env.GetEnvironment().GetId()})
	wantCode(t, "other org ArchiveEnvironment", err, connect.CodeNotFound)
	_, err = oacc.GetUser(ctx, &pantherclawv1.GetUserRequest{Id: adminID.String()})
	wantCode(t, "other org GetUser", err, connect.CodeNotFound)
	_, err = oacc.DeleteRoleBinding(ctx, &pantherclawv1.DeleteRoleBindingRequest{Id: b.GetBinding().GetId()})
	wantCode(t, "other org DeleteRoleBinding", err, connect.CodeNotFound)

	// No credentials.
	nten, _ := s.clients("")
	_, err = nten.GetOrg(ctx, &pantherclawv1.GetOrgRequest{})
	wantCode(t, "anonymous", err, connect.CodeUnauthenticated)

	// Disabling the viewer revokes its session: its token stops working.
	if _, err := acc.SetUserState(ctx, &pantherclawv1.SetUserStateRequest{
		Id: viewerID.String(), State: pantherclawv1.AccountState_ACCOUNT_STATE_DISABLED,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = vten.GetTeam(ctx, &pantherclawv1.GetTeamRequest{Id: teamID})
	wantCode(t, "disabled viewer", err, connect.CodeUnauthenticated)
}

func (s *stack) saClient(tok string) pantherclawv1connect.ServiceAccountServiceClient {
	tr := connecthttp.NewTransport(&http.Client{Transport: bearer{tok}}, s.url)
	return pantherclawv1connect.NewServiceAccountServiceClient(connect.NewClient(tr))
}
