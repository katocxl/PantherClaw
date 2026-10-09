// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type clusters map[string]ids.OrgID

func (c clusters) Allowed(name string, org ids.OrgID) bool { return c[name] == org }

const (
	mainRef = "octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/main"
	tagRef  = "octo-org/agent-repo/.github/workflows/agent.yml@refs/tags/v1"
)

func gh(refs ...string) app.Binding {
	return app.Binding{GitHub: &issuers.GitHubBinding{
		RepositoryID: "123456", RepositoryOwnerID: "7890", JobType: issuers.JobWorkflow, WorkflowRefs: refs,
	}}
}

// orgAdmin proposes (identity.issuer.manage); publisher activates.
func (w *world) orgAdmin() context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
}

func (w *world) publisher(kind td.PrincipalKind) context.Context {
	return w.person(ids.NewV7(), kind, td.RoleIdentityPublisher)
}

func (w *world) activeEntries(t *testing.T) int {
	return w.count(t, "SELECT count(*) FROM pc.trusted_issuers WHERE org_id = $1 AND state = 'ACTIVE'", w.org)
}

// TestHR141_WideningWaitsForAPersonToActivate.
func TestHR141_WideningWaitsForAPersonToActivate(t *testing.T) {
	w := newWorld(t)
	agent := w.agent(t, adomain.ContextCI)
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: gh(mainRef), Reason: "CI agent"}, nil)
	if err != nil || r.State != "PROPOSED" || len(r.Widening) == 0 || w.activeEntries(t) != 0 {
		t.Fatalf("propose: %+v, %v", r, err)
	}
	_, err = w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{EntryID: r.EntryID, AgentID: agent, Binding: gh(mainRef), Reason: "again"}, nil)
	wantCode(t, "second proposal", err, pcerr.FailedPrecondition, "ISSUER_PROPOSAL_OPEN")
	_, err = w.svc.ActivateIssuer(w.publisher(td.KindServiceAccount), r.EntryID, r.Revision, false)
	wantCode(t, "service account activates", err, pcerr.PermissionDenied, "")
	_, err = w.svc.ActivateIssuer(w.orgAdmin(), r.EntryID, r.Revision, false)
	wantCode(t, "Org Admin activates", err, pcerr.PermissionDenied, "")
	if a, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), r.EntryID, r.Revision, false); err != nil || a.State != "ACTIVE" {
		t.Fatalf("activate: %+v, %v", a, err)
	}
	// Adding a ref widens: the active revision keeps working until activation.
	r2, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{EntryID: r.EntryID, AgentID: agent, Binding: gh(mainRef, tagRef), Reason: "release tags"}, nil)
	if err != nil || r2.State != "PROPOSED" || r2.Revision != 2 {
		t.Fatalf("widen: %+v, %v", r2, err)
	}
	revs, _ := w.svc.GetIssuer(w.orgAdmin(), r.EntryID)
	if len(revs) != 2 || revs[1].State != "ACTIVE" {
		t.Fatalf("while proposed: %+v", revs)
	}
	if _, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), r.EntryID, 2, false); err != nil {
		t.Fatal(err)
	}
	// Removing a ref only narrows: it replaces the active revision at once.
	r3, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{EntryID: r.EntryID, AgentID: agent, Binding: gh(mainRef), Reason: "drop tags"}, nil)
	if err != nil || r3.State != "ACTIVE" || len(r3.Widening) != 0 || w.activeEntries(t) != 1 {
		t.Fatalf("narrow: %+v, %v", r3, err)
	}
	// Turning on auto-admission is a widening.
	r4, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{EntryID: r.EntryID, AgentID: agent, Binding: gh(mainRef), AutoAdmit: true, Reason: "auto"}, nil)
	if err != nil || r4.State != "PROPOSED" {
		t.Fatalf("auto-admit: %+v, %v", r4, err)
	}
	d, err := w.svc.DisableIssuer(w.orgAdmin(), r.EntryID, "repository archived")
	if err != nil || d.State != "DISABLED" || w.activeEntries(t) != 0 ||
		w.count(t, "SELECT count(*) FROM pc.trusted_issuers WHERE org_id = $1 AND state = 'PROPOSED'", w.org) != 0 {
		t.Fatalf("disable: %+v, %v", d, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.identity.issuer_%'", w.org); n != 7 {
		t.Errorf("issuer audit events %d, want 7", n)
	}
}

// TestHR140_EntriesFitTheAgentAndTheConfiguration.
func TestHR140_EntriesFitTheAgentAndTheConfiguration(t *testing.T) {
	w := newWorld(t)
	desktop := w.agent(t, adomain.ContextDesktop)
	_, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: desktop, Binding: gh(mainRef), Reason: "x"}, nil)
	wantCode(t, "GitHub preset for a desktop agent", err, pcerr.InvalidArgument, "ISSUER_CONTEXT")
	ci := w.agent(t, adomain.ContextCI)
	bad := gh(mainRef)
	bad.GitHub.RepositoryID = "octo-org/agent-repo"
	_, err = w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: ci, Binding: bad, Reason: "x"}, nil)
	wantCode(t, "repository name instead of id", err, pcerr.InvalidArgument, "ISSUER_BINDING")
	pod := w.agent(t, adomain.ContextKubernetes)
	kb := app.Binding{Kubernetes: &issuers.KubernetesBinding{
		Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f",
	}}
	_, err = w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: pod, Binding: kb, Reason: "x"}, clusters{"prod": ids.New[ids.Org]()})
	wantCode(t, "cluster configured for another org", err, pcerr.InvalidArgument, "ISSUER_CLUSTER")
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: pod, Binding: kb, Reason: "x"}, clusters{"prod": w.org}); err != nil {
		t.Fatalf("configured cluster: %v", err)
	}
	reusable := app.Binding{GitHub: &issuers.GitHubBinding{
		RepositoryID: "123456", RepositoryOwnerID: "7890", JobType: issuers.JobReusable,
		WorkflowRefs: []string{"octo-org/workflows/.github/workflows/agent.yml@refs/tags/v1"},
	}}
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: ci, Binding: reusable, Reason: "shared workflow"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.ActivateIssuer(w.publisher(td.KindUser), r.EntryID, r.Revision, false)
	wantCode(t, "reusable refs not confirmed", err, pcerr.FailedPrecondition, "CONFIRM_REUSABLE_REFS")
	if _, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), r.EntryID, r.Revision, true); err != nil {
		t.Fatal(err)
	}
	l, _, err := w.svc.ListIssuers(w.orgAdmin(), ids.UUID{}, page.Request{Size: 10})
	if err != nil || len(l) != 2 {
		t.Fatalf("list: %d, %v", len(l), err)
	}
	// Another org's entries are invisible (T-037).
	other := newWorld(t)
	_, err = other.svc.GetIssuer(other.orgAdmin(), r.EntryID)
	wantCode(t, "another org's entry", err, pcerr.NotFound, "")
	_, err = other.svc.ActivateIssuer(other.publisher(td.KindUser), r.EntryID, r.Revision, true)
	wantCode(t, "another org activates", err, pcerr.NotFound, "")
}
