// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

type world struct {
	d                *dbtest.DB
	pool             *db.Pool
	svc              *app.Service
	inv              *aapp.Inventory
	org              ids.OrgID
	team, env, owner ids.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	w := &world{
		d: d, pool: p, svc: app.New(p), inv: aapp.NewInventory(p, unlimited{}),
		org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(),
	}
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	return w
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (w *world) as(kind td.PrincipalKind, id ids.UUID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeTeam, ID: w.team}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

func (w *world) ownerCtx() context.Context { return w.as(td.KindUser, w.owner, td.RoleAgentOwner) }

func (w *world) agent(t *testing.T) ids.UUID {
	t.Helper()
	a, err := w.inv.Create(w.ownerCtx(), adomain.Details{
		Name: "coder", TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner, Context: adomain.ContextCI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// instance inserts an instance of agent in state.
func (w *world) instance(t *testing.T, agent ids.UUID, state string) pap.Instance {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := ids.NewV7()
	w.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, expires_at)
		VALUES ($1, $2, $3, $4, '{}', $5, 'discovery', now() + interval '1 day')`,
		w.org, id, agent, base64.RawURLEncoding.EncodeToString(b), state)
	return pap.Instance{Org: w.org, Agent: agent, Instance: id}
}

func wantCode(t *testing.T, what string, err error, code pcerr.Code, reason string) {
	t.Helper()
	if pcerr.CodeOf(err) != code || (reason != "" && pcerr.ReasonOf(err) != reason) {
		t.Errorf("%s: err = %v, want %s %s", what, err, code, reason)
	}
}

func wantPAP(t *testing.T, what string, err error, code pap.Code) {
	t.Helper()
	if !errors.Is(err, pap.Err(code)) {
		t.Errorf("%s: err = %v, want %s", what, err, code)
	}
}

// TestHR146_TheLauncherIsThePrincipal: without a subject token, the run
// represents whoever started it; nothing names another principal.
func TestHR146_TheLauncherIsThePrincipal(t *testing.T) {
	w := newWorld(t)
	agent := w.agent(t)
	r, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, TaskRef: "refund #42"})
	if err != nil || r.PrincipalSource != app.SourceLauncher || r.Principal != r.Launcher ||
		r.Launcher != (app.Actor{Kind: "user", ID: w.owner.String()}) || len(r.ActorChain) != 1 || r.Depth != 0 {
		t.Fatalf("user launcher: %+v, %v", r, err)
	}
	if d := time.Until(r.ExpiresAt); d < app.DefaultTTL-time.Minute || d > app.DefaultTTL+time.Minute {
		t.Errorf("default lifetime %s", d)
	}
	sa := ids.NewV7()
	w.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", w.org, sa)
	r, err = w.svc.StartRun(w.as(td.KindServiceAccount, sa, td.RoleDeveloper), app.StartInput{AgentID: agent})
	if err != nil || r.Principal != (app.Actor{Kind: "service_account", ID: sa.String()}) || r.Principal != r.Launcher {
		t.Fatalf("service account launcher: %+v, %v", r, err)
	}
	_, err = w.svc.StartRun(w.as(td.KindUser, w.owner, td.RoleViewer), app.StartInput{AgentID: agent})
	wantCode(t, "without run.start", err, pcerr.PermissionDenied, "")
	_, err = w.svc.StartRun(w.as(td.KindUser, w.owner, td.RoleRunLauncher), app.StartInput{
		AgentID: agent, SubjectToken: "eyJ.x.y", SubjectTokenType: "SUBJECT_TOKEN_TYPE_ID_TOKEN",
	})
	wantCode(t, "subject token", err, pcerr.FailedPrecondition, "SUBJECT_TOKEN_UNAVAILABLE")
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.run.started'", w.org); n != 2 {
		t.Errorf("run.started events %d, want 2", n)
	}
}

// TestHR022_RunsBindOnlyToTheirAgentsAdmittedInstances.
func TestHR022_RunsBindOnlyToTheirAgentsAdmittedInstances(t *testing.T) {
	w := newWorld(t)
	agent, other := w.agent(t), w.agent(t)
	pending, foreign, ok := w.instance(t, agent, "PENDING_ADMISSION"), w.instance(t, other, "ADMITTED"), w.instance(t, agent, "ADMITTED")
	for name, inst := range map[string]pap.Instance{"pending": pending, "another agent's": foreign} {
		_, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, InstanceID: &inst.Instance})
		wantCode(t, name+" instance", err, pcerr.FailedPrecondition, "INSTANCE_STATE")
	}
	r, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, InstanceID: &ok.Instance, TTL: time.Hour})
	if err != nil || r.InstanceID == nil || *r.InstanceID != ok.Instance {
		t.Fatalf("bound run: %+v, %v", r, err)
	}
	_, err = w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, TTL: 25 * time.Hour})
	wantCode(t, "over 24 hours", err, pcerr.InvalidArgument, "RUN_TTL")
	_, err = w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, TaskRef: string(make([]byte, 257))})
	wantCode(t, "long task_ref", err, pcerr.InvalidArgument, "TASK_REF")
	if _, err := w.inv.Suspend(w.ownerCtx(), agent, "investigating"); err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent})
	wantCode(t, "suspended agent", err, pcerr.FailedPrecondition, "AGENT_STATE")
	// Another org sees nothing (T-037).
	o := newWorld(t)
	_, err = o.svc.GetRun(o.ownerCtx(), r.ID)
	wantCode(t, "another org's run", err, pcerr.NotFound, "")
	_, err = o.svc.EndRun(o.ownerCtx(), r.ID, "done")
	wantCode(t, "another org ends", err, pcerr.NotFound, "")
	_, err = o.svc.StartRun(o.ownerCtx(), app.StartInput{AgentID: other})
	wantCode(t, "another org's agent", err, pcerr.NotFound, "")
}

// TestHR022_ChildRunsStayInsideTheirParent: only the instance the parent
// is bound to starts children; they inherit its principal, never outlive
// it, nest at most 8 deep and end with it.
func TestHR022_ChildRunsStayInsideTheirParent(t *testing.T) {
	w := newWorld(t)
	agent, helper := w.agent(t), w.agent(t)
	inst, stranger := w.instance(t, agent, "ADMITTED"), w.instance(t, agent, "ADMITTED")
	root, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, InstanceID: &inst.Instance, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: stranger, ParentRunID: root.ID, AgentID: helper})
	wantPAP(t, "another instance's run", err, pap.CodeRunMismatch)
	unbound, _ := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent})
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: unbound.ID, AgentID: helper})
	wantPAP(t, "unbound parent", err, pap.CodeRunMismatch)
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: ids.NewV7(), AgentID: helper})
	wantPAP(t, "unknown parent", err, pap.CodeRunMismatch)
	child, err := w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: root.ID, AgentID: helper, TTL: 3 * time.Hour})
	if err != nil || child.Principal != root.Principal || child.PrincipalSource != app.SourceParentRun ||
		child.Launcher != (app.Actor{Kind: "instance", ID: inst.Instance.String()}) || len(child.ActorChain) != 2 ||
		child.Depth != 1 || child.ExpiresAt.After(root.ExpiresAt) {
		t.Fatalf("child: %+v, %v", child, err)
	}
	parent := root
	for depth := 1; depth <= app.MaxDepth; depth++ {
		parent, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: parent.ID, AgentID: agent, InstanceID: &inst.Instance})
		if err != nil || parent.Depth != depth {
			t.Fatalf("depth %d: %+v, %v", depth, parent, err)
		}
	}
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: parent.ID, AgentID: agent})
	wantCode(t, "ninth level", err, pcerr.FailedPrecondition, "RUN_DEPTH")
	ended, err := w.svc.EndRun(w.ownerCtx(), root.ID, "task done")
	if err != nil || ended.State != "ENDED" || ended.EndReason != "task done" {
		t.Fatalf("end: %+v, %v", ended, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND state = 'REVOKED' AND end_reason = 'parent_ended'", w.org); n != app.MaxDepth+1 {
		t.Fatalf("revoked descendants %d, want %d", n, app.MaxDepth+1)
	}
	_, err = w.svc.EndRun(w.ownerCtx(), root.ID, "again")
	wantCode(t, "ending twice", err, pcerr.FailedPrecondition, "RUN_STATE")
	_, err = w.svc.StartChildRun(ctx, app.ChildInput{Caller: inst, ParentRunID: root.ID, AgentID: helper})
	wantPAP(t, "ended parent", err, pap.CodeRunMismatch)
	_, err = w.svc.EndRun(w.as(td.KindUser, w.owner, td.RoleDeveloper), unbound.ID, "x")
	wantCode(t, "without run.manage", err, pcerr.PermissionDenied, "")
}

// TestHR022_RetiringAnAgentRevokesItsRunTree: retirement revokes the
// agent's runs and every child run below them (F023).
func TestHR022_RetiringAnAgentRevokesItsRunTree(t *testing.T) {
	w := newWorld(t)
	agent, helper := w.agent(t), w.agent(t)
	inst := w.instance(t, agent, "ADMITTED")
	root, err := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: agent, InstanceID: &inst.Instance})
	if err != nil {
		t.Fatal(err)
	}
	child, err := w.svc.StartChildRun(context.Background(), app.ChildInput{Caller: inst, ParentRunID: root.ID, AgentID: helper})
	if err != nil {
		t.Fatal(err)
	}
	keep, _ := w.svc.StartRun(w.ownerCtx(), app.StartInput{AgentID: helper})
	if _, err := w.inv.Retire(w.ownerCtx(), agent, "replaced"); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[ids.UUID]string{root.ID: "REVOKED", child.ID: "REVOKED", keep.ID: "ACTIVE"} {
		if r, err := w.svc.GetRun(w.ownerCtx(), id); err != nil || r.State != want {
			t.Errorf("run %s: %+v, %v; want %s", id, r.State, err, want)
		}
	}
	l, err := w.svc.ListRuns(w.ownerCtx(), page.Request{Size: 10}, nil, []string{"ACTIVE"})
	if err != nil || len(l.Items) != 1 || l.Items[0].ID != keep.ID {
		t.Fatalf("active runs: %+v, %v", l, err)
	}
	if l, _ := w.svc.ListRuns(w.as(td.KindUser, ids.NewV7()), page.Request{Size: 10}, nil, nil); len(l.Items) != 0 {
		t.Errorf("a caller without run.read listed %d runs", len(l.Items))
	}
}

// TestHR146_SubjectTokensRepresentActiveUsersOnce: a launcher with
// run.represent presents a provider token; the run then represents that
// user, the token is single use, the user must already be active, and the
// run's authority is the same as without a token (no grant in M3).
func TestHR146_SubjectTokensRepresentActiveUsersOnce(t *testing.T) {
	w := newWorld(t)
	idp := oidctest.New(t)
	p, err := oidcrp.New(oidcrp.Config{
		Name: "corp", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(), SubjectTokenAudience: "https://pc.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(w.pool).WithSubjects(oidcrp.Subjects{p})
	alice, bob := ids.NewV7(), ids.NewV7()
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'alice')", w.org, alice, idp.Issuer())
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject, state) VALUES ($1, $2, $3, 'bob', 'DISABLED')", w.org, bob, idp.Issuer())
	sa := ids.NewV7()
	w.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'portal', 'test')", w.org, sa)
	launcher := w.as(td.KindServiceAccount, sa, td.RoleRunLauncher)
	agent := w.agent(t)
	token := func(sub string) string {
		now := time.Now()
		return idp.Token(map[string]any{
			"iss": idp.Issuer(), "sub": sub, "aud": "https://pc.example.test", "jti": ids.NewV7().String(),
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		}, "")
	}
	start := func(ctx context.Context, tok, typ string) (app.Run, error) {
		return svc.StartRun(ctx, app.StartInput{AgentID: agent, SubjectToken: tok, SubjectTokenType: typ})
	}
	tok := token("alice")
	_, err = start(w.as(td.KindUser, w.owner, td.RoleDeveloper), tok, app.SubjectIDToken)
	wantCode(t, "without run.represent", err, pcerr.PermissionDenied, "")
	r, err := start(launcher, tok, app.SubjectIDToken)
	if err != nil || r.PrincipalSource != app.SourceSubjectToken || r.Principal != (app.Actor{Kind: "user", ID: alice.String()}) ||
		r.Launcher != (app.Actor{Kind: "service_account", ID: sa.String()}) || r.SubjectIssuer != idp.Issuer() ||
		r.SubjectSubject != "alice" || len(r.ActorChain) != 2 {
		t.Fatalf("represented run (the refused attempt must not consume the token): %+v, %v", r, err)
	}
	_, err = start(launcher, tok, app.SubjectIDToken)
	wantCode(t, "reused token", err, pcerr.PermissionDenied, "SUBJECT_TOKEN")
	for name, tc := range map[string][2]string{
		"disabled user":      {token("bob"), app.SubjectIDToken},
		"unknown user":       {token("carol"), app.SubjectIDToken},
		"ID token as access": {token("alice"), app.SubjectAccessToken},
	} {
		_, err := start(launcher, tc[0], tc[1])
		wantCode(t, name, err, pcerr.PermissionDenied, "SUBJECT_TOKEN")
	}
	_, err = start(launcher, token("alice"), "")
	wantCode(t, "no token type", err, pcerr.InvalidArgument, "SUBJECT_TOKEN_TYPE")
	if n := w.count(t, "SELECT count(*) FROM pc.users WHERE org_id = $1", w.org); n != 3 {
		t.Errorf("users %d: a subject token created one", n)
	}
	self, err := svc.StartRun(launcher, app.StartInput{AgentID: agent})
	if err != nil || self.PrincipalSource != app.SourceLauncher {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND grant_id IS NOT NULL", w.org); n != 0 {
		t.Errorf("%d runs carry a grant", n)
	}
}
