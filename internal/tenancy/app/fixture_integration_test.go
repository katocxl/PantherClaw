// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type fakeEnts struct{ edition billing.Edition }

func (f *fakeEnts) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition = f.edition
	return e, nil
}

type fixture struct {
	d    *dbtest.DB
	pool *db.Pool
	ents *fakeEnts
	h    *app.Hierarchy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	ents := &fakeEnts{edition: billing.Business}
	return &fixture{d: d, pool: p, ents: ents, h: app.NewHierarchy(p, ents)}
}

// org creates an org with its containment row, as `org create` does.
func (f *fixture) org(t *testing.T, name string) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, name)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return org
}

// user inserts an active user.
func (f *fixture) user(t *testing.T, org ids.OrgID, email string) td.UserID {
	t.Helper()
	id := ids.New[td.User]()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.users (org_id, id, issuer, subject, email, display_name)
			VALUES ($1, $2, 'https://idp.example.test', $3, $3, $3)`, org, id, email)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// as returns ctx for a user of org holding the given bindings.
func as(org ids.OrgID, bs ...td.Binding) context.Context {
	c := app.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs},
		Credential: app.CredAccessToken,
	}
	return app.WithCaller(context.Background(), c)
}

func orgRole(org ids.OrgID, r td.RoleName) td.Binding {
	return td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}
}

func scoped(r td.RoleName, t td.ScopeType, id ids.UUID) td.Binding {
	return td.Binding{Role: r, Scope: td.Scope{Type: t, ID: id}}
}

func adminOf(org ids.OrgID) context.Context { return as(org, orgRole(org, td.RoleOrgAdmin)) }

// wantCode fails unless err has the platform code (and reason, if given).
func wantCode(t *testing.T, what string, err error, code pcerr.Code, reason string) {
	t.Helper()
	if pcerr.CodeOf(err) != code || (reason != "" && pcerr.ReasonOf(err) != reason) {
		t.Errorf("%s: err = %v, want %s %s", what, err, code, reason)
	}
}

// must returns v or panics: for setup steps that cannot fail in a healthy
// test database (a panic still fails the test with a stack trace).
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// auditCount counts ledger entries of an audit event name in org.
func (f *fixture) auditCount(t *testing.T, org ids.OrgID, name string) int {
	t.Helper()
	var n int
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", org, "audit."+name).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dbqNew(tx db.TenantTx) *dbq.Queries { return dbq.New(tx) }
