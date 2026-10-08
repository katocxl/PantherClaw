// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"sync"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func ptr(s string) *string { return &s }

func TestIntTenancyHierarchyLifecycle(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "acme")
	ctx := adminOf(org)
	all := page.Request{Size: page.Default}

	o := must(f.h.UpdateOrg(ctx, "  Acme Corp "))
	if o.Name != "Acme Corp" || o.ID != org {
		t.Fatalf("org = %+v", o)
	}
	bu := must(f.h.CreateBusinessUnit(ctx, app.NewEntity{Slug: "payments", Name: "Payments", Description: "money"}))
	tm := must(f.h.CreateTeam(ctx, bu.ID, app.NewEntity{Slug: "refunds", Name: "Refunds"}))
	env := must(f.h.CreateEnvironment(ctx, tm.ID, td.Production, app.NewEntity{Slug: "prod", Name: "Production"}))
	orgEnv := must(f.h.CreateEnvironment(ctx, ids.ID[td.Team]{}, td.Development, app.NewEntity{Slug: "prod", Name: "Org prod"}))
	if tm.BusinessUnit != bu.ID || env.Team != tm.ID || !orgEnv.Team.IsZero() {
		t.Fatal("parents not recorded")
	}

	_, err := f.h.CreateTeam(ctx, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "refunds", Name: "Again"})
	wantCode(t, "duplicate team slug", err, pcerr.AlreadyExists, "SLUG_TAKEN")
	_, err = f.h.CreateEnvironment(ctx, tm.ID, td.Staging, app.NewEntity{Slug: "prod", Name: "Dup"})
	wantCode(t, "duplicate environment slug in team", err, pcerr.AlreadyExists, "SLUG_TAKEN")

	// Update changes only the fields that are set (no mass assignment).
	upd := must(f.h.UpdateBusinessUnit(ctx, bu.ID, ptr("Payments EU"), nil))
	if upd.Name != "Payments EU" || upd.Description != "money" || upd.Slug != "payments" {
		t.Fatalf("update = %+v", upd)
	}
	_, err = f.h.UpdateTeam(ctx, tm.ID, ptr("bad\x00name"), nil)
	wantCode(t, "control character in name", err, pcerr.InvalidArgument, "")

	// Members.
	alice := f.user(t, org, "alice@example.test")
	m := must(f.h.AddTeamMember(ctx, tm.ID, alice))
	if m.Email != "alice@example.test" {
		t.Fatalf("member = %+v", m)
	}
	_, err = f.h.AddTeamMember(ctx, tm.ID, alice)
	wantCode(t, "duplicate member", err, pcerr.AlreadyExists, "ALREADY_MEMBER")
	_, err = f.h.AddTeamMember(ctx, tm.ID, ids.New[td.User]())
	wantCode(t, "unknown user", err, pcerr.NotFound, "USER_NOT_FOUND")
	if ms := must(f.h.ListTeamMembers(ctx, tm.ID, all)); len(ms.Items) != 1 {
		t.Fatalf("members = %+v", ms)
	}
	if err := f.h.RemoveTeamMember(ctx, tm.ID, alice); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "remove twice", f.h.RemoveTeamMember(ctx, tm.ID, alice), pcerr.NotFound, "MEMBER_NOT_FOUND")

	// Archive bottom-up only.
	_, err = f.h.ArchiveBusinessUnit(ctx, bu.ID)
	wantCode(t, "archive non-empty business unit", err, pcerr.FailedPrecondition, "NOT_EMPTY")
	_, err = f.h.ArchiveTeam(ctx, tm.ID)
	wantCode(t, "archive team with environment", err, pcerr.FailedPrecondition, "NOT_EMPTY")
	must(f.h.ArchiveEnvironment(ctx, env.ID))
	must(f.h.ArchiveTeam(ctx, tm.ID))
	must(f.h.ArchiveBusinessUnit(ctx, bu.ID))
	_, err = f.h.UpdateTeam(ctx, tm.ID, ptr("x"), nil)
	wantCode(t, "update archived team", err, pcerr.FailedPrecondition, "ARCHIVED")
	_, err = f.h.CreateTeam(ctx, bu.ID, app.NewEntity{Slug: "late", Name: "Late"})
	wantCode(t, "team under archived business unit", err, pcerr.FailedPrecondition, "ARCHIVED")
	_, err = f.h.CreateEnvironment(ctx, tm.ID, td.Staging, app.NewEntity{Slug: "late", Name: "Late"})
	wantCode(t, "environment under archived team", err, pcerr.FailedPrecondition, "ARCHIVED")

	if l := must(f.h.ListTeams(ctx, all, ids.ID[td.BusinessUnit]{}, false)); len(l.Items) != 0 {
		t.Fatalf("archived team listed: %+v", l.Items)
	}
	if l := must(f.h.ListTeams(ctx, all, bu.ID, true)); len(l.Items) != 1 {
		t.Fatalf("include_archived by business unit: %+v", l.Items)
	}

	// Every change is in the evidence ledger (F585).
	for name, want := range map[string]int{
		"tenancy.org_updated": 1, "tenancy.business_unit_created": 1, "tenancy.team_created": 1,
		"tenancy.environment_created": 2, "tenancy.team_member_added": 1, "tenancy.team_member_removed": 1,
		"tenancy.business_unit_archived": 1, "tenancy.team_archived": 1, "tenancy.environment_archived": 1,
	} {
		if got := f.auditCount(t, org, name); got != want {
			t.Errorf("audit %s = %d, want %d", name, got, want)
		}
	}
}

func TestIntBusinessUnitsNeedBusinessEdition(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "small")
	f.ents.edition = billing.Community
	_, err := f.h.CreateBusinessUnit(adminOf(org), app.NewEntity{Slug: "bu", Name: "BU"})
	wantCode(t, "community edition", err, pcerr.FailedPrecondition, "EDITION_REQUIRED")
	// Small tenants still get teams and environments.
	must(f.h.CreateTeam(adminOf(org), ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "team", Name: "Team"}))
}

// TestT037_TenancyIDOR: another org's ids are NotFound for every read and
// change, even for that other org's admin, and never appear in lists.
func TestT037_TenancyIDOR(t *testing.T) {
	f := newFixture(t)
	a, b := f.org(t, "a"), f.org(t, "b")
	ctxA, ctxB := adminOf(a), adminOf(b)
	bu := must(f.h.CreateBusinessUnit(ctxA, app.NewEntity{Slug: "bu", Name: "BU"}))
	tm := must(f.h.CreateTeam(ctxA, bu.ID, app.NewEntity{Slug: "t", Name: "T"}))
	env := must(f.h.CreateEnvironment(ctxA, tm.ID, td.Production, app.NewEntity{Slug: "e", Name: "E"}))
	alice := f.user(t, a, "alice@a.test")

	checks := map[string]error{}
	_, checks["get bu"] = f.h.GetBusinessUnit(ctxB, bu.ID)
	_, checks["update bu"] = f.h.UpdateBusinessUnit(ctxB, bu.ID, ptr("pwn"), nil)
	_, checks["archive bu"] = f.h.ArchiveBusinessUnit(ctxB, bu.ID)
	_, checks["team in foreign bu"] = f.h.CreateTeam(ctxB, bu.ID, app.NewEntity{Slug: "x", Name: "X"})
	_, checks["get team"] = f.h.GetTeam(ctxB, tm.ID)
	_, checks["update team"] = f.h.UpdateTeam(ctxB, tm.ID, ptr("pwn"), nil)
	_, checks["archive team"] = f.h.ArchiveTeam(ctxB, tm.ID)
	_, checks["add member"] = f.h.AddTeamMember(ctxB, tm.ID, alice)
	checks["remove member"] = f.h.RemoveTeamMember(ctxB, tm.ID, alice)
	_, checks["list members"] = f.h.ListTeamMembers(ctxB, tm.ID, page.Request{Size: 10})
	_, checks["env in foreign team"] = f.h.CreateEnvironment(ctxB, tm.ID, td.Staging, app.NewEntity{Slug: "x", Name: "X"})
	_, checks["get env"] = f.h.GetEnvironment(ctxB, env.ID)
	_, checks["update env"] = f.h.UpdateEnvironment(ctxB, env.ID, ptr("pwn"), nil)
	_, checks["archive env"] = f.h.ArchiveEnvironment(ctxB, env.ID)
	for name, err := range checks {
		wantCode(t, name, err, pcerr.NotFound, "")
	}
	// B's own team cannot take A's user as a member.
	tb := must(f.h.CreateTeam(ctxB, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "t", Name: "T"}))
	_, err := f.h.AddTeamMember(ctxB, tb.ID, alice)
	wantCode(t, "foreign user", err, pcerr.NotFound, "USER_NOT_FOUND")

	all := page.Request{Size: page.Max}
	if l := must(f.h.ListBusinessUnits(ctxB, all, true)); len(l.Items) != 0 {
		t.Errorf("B lists A's business units: %+v", l.Items)
	}
	if l := must(f.h.ListEnvironments(ctxB, all, tm.ID, true)); len(l.Items) != 0 {
		t.Errorf("B lists A's environments by A's team id: %+v", l.Items)
	}
	if got := must(f.h.GetEnvironment(ctxA, env.ID)); got.Name != "E" {
		t.Errorf("A's environment changed: %+v", got)
	}
}

// TestT037_ScopedRolesActOnlyInTheirSubtree: a team-scoped role manages that
// team's environments only; lists show only what the caller may read; a
// caller without the permission is refused even inside its org.
func TestT037_ScopedRolesActOnlyInTheirSubtree(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "acme")
	admin := adminOf(org)
	t1 := must(f.h.CreateTeam(admin, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "one", Name: "One"}))
	t2 := must(f.h.CreateTeam(admin, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "two", Name: "Two"}))
	e2 := must(f.h.CreateEnvironment(admin, t2.ID, td.Staging, app.NewEntity{Slug: "s", Name: "S"}))

	// No default role manages environments below org scope, so give a
	// team-scoped viewer and check reads, then an org viewer for writes.
	viewer1 := as(org, scoped(td.RoleViewer, td.ScopeTeam, t1.ID.UUID()))
	must(f.h.GetTeam(viewer1, t1.ID))
	_, err := f.h.GetTeam(viewer1, t2.ID)
	wantCode(t, "read sibling team", err, pcerr.PermissionDenied, "PERMISSION_DENIED")
	_, err = f.h.GetEnvironment(viewer1, e2.ID)
	wantCode(t, "read sibling team's environment", err, pcerr.PermissionDenied, "PERMISSION_DENIED")
	teams := must(f.h.ListTeams(viewer1, page.Request{Size: page.Max}, ids.ID[td.BusinessUnit]{}, false))
	if len(teams.Items) != 1 || teams.Items[0].ID != t1.ID {
		t.Errorf("scoped viewer lists %+v, want only team one", teams.Items)
	}
	_, err = f.h.CreateEnvironment(viewer1, t1.ID, td.Staging, app.NewEntity{Slug: "x", Name: "X"})
	wantCode(t, "viewer creates environment", err, pcerr.PermissionDenied, "PERMISSION_DENIED")

	orgViewer := as(org, orgRole(org, td.RoleViewer))
	member := f.user(t, org, "v@x.test")
	for name, err := range map[string]error{
		"update org": func() error { _, err := f.h.UpdateOrg(orgViewer, "x"); return err }(),
		"create team": func() error {
			_, err := f.h.CreateTeam(orgViewer, ids.ID[td.BusinessUnit]{}, app.NewEntity{Slug: "x", Name: "X"})
			return err
		}(),
		"add member": func() error { _, err := f.h.AddTeamMember(orgViewer, t1.ID, member); return err }(),
	} {
		wantCode(t, name, err, pcerr.PermissionDenied, "PERMISSION_DENIED")
	}
	if _, err := f.h.GetOrg(context.Background()); pcerr.CodeOf(err) != pcerr.Unauthenticated {
		t.Errorf("no caller: %v", err)
	}
}

// TestRace_ArchiveVsCreateChild: concurrent archive of a business unit and
// creation of a team under it never leave an active team in an archived
// unit.
func TestRace_ArchiveVsCreateChild(t *testing.T) {
	f := newFixture(t)
	org := f.org(t, "race")
	ctx := adminOf(org)
	for i := range 20 {
		bu := must(f.h.CreateBusinessUnit(ctx, app.NewEntity{Slug: "bu-" + string(rune('a'+i)), Name: "BU"}))
		var wg sync.WaitGroup
		var archErr, createErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, archErr = f.h.ArchiveBusinessUnit(ctx, bu.ID) }()
		go func() {
			defer wg.Done()
			_, createErr = f.h.CreateTeam(ctx, bu.ID, app.NewEntity{Slug: "t-" + string(rune('a'+i)), Name: "T"})
		}()
		wg.Wait()
		if archErr == nil && createErr == nil {
			t.Fatalf("round %d: unit archived and team created under it", i)
		}
		got := must(f.h.GetBusinessUnit(ctx, bu.ID))
		teams := must(f.h.ListTeams(ctx, page.Request{Size: 10}, bu.ID, false))
		if got.State == td.Archived && len(teams.Items) > 0 {
			t.Fatalf("round %d: active team in archived unit", i)
		}
	}
}
