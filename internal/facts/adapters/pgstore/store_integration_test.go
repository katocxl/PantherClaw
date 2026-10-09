// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type allow struct{}

func (allow) Require(tapp.Caller, tdomain.Permission, tdomain.Path) error { return nil }

func as(org ids.OrgID, kind tdomain.PrincipalKind, id ids.UUID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: org, Principal: tdomain.PrincipalRef{Kind: kind, ID: id}}})
}

var refundable = []domain.Declaration{{Name: "payments.charge.refundable", Type: domain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute}}

func obs(value string, at time.Time) domain.Observation {
	return domain.Observation{Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: "ch_1", Value: jsontext.Value(value), ObservedAt: at}
}

func TestHR160_FactsOnlyFromTheProvidersServiceAccount(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org, alice, sa1, sa2 := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", []any{org}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{org, alice}},
			{"INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", []any{org, sa1}},
			{"INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", []any{org, sa2}},
		} {
			if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store := &pgstore.Store{Pool: p}
	svc := &app.Service{Store: store, Authz: allow{}}
	human := as(org, tdomain.KindUser, alice)
	prov, err := svc.RegisterProvider(human, "billing.system", sa1, refundable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterProvider(human, "rival.system", sa2, refundable); err == nil {
		t.Fatal("a second provider registered for the same fact")
	}
	if _, err := svc.RegisterProvider(as(org, tdomain.KindServiceAccount, sa1), "self.system", sa1, nil); !errors.Is(err, app.ErrHumanOnly) {
		t.Fatalf("a service account registered a provider: %v", err)
	}

	now := time.Now().UTC()
	res, err := svc.PutFacts(as(org, tdomain.KindServiceAccount, sa1), []domain.Observation{obs(`{"bool": true}`, now.Add(-time.Minute))})
	if err != nil || res[0].Err != nil {
		t.Fatalf("the provider's own push: %v %+v", err, res)
	}
	for name, ctx := range map[string]context.Context{"another service account": as(org, tdomain.KindServiceAccount, sa2), "a person": human} {
		if _, err := svc.PutFacts(ctx, []domain.Observation{obs(`{"bool": false}`, now)}); !errors.Is(err, app.ErrNotProvider) {
			t.Fatalf("%s pushed a fact: %v", name, err)
		}
	}
	other := obs(`{"bool": true}`, now)
	other.Name = "payments.charge.disputed"
	stale := obs(`{"bool": false}`, now.Add(-2*time.Minute))
	res, err = svc.PutFacts(as(org, tdomain.KindServiceAccount, sa1), []domain.Observation{other, stale, obs(`{"bool": false}`, now.Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(res[0].Err, domain.ErrUntrusted) || !errors.Is(res[1].Err, domain.ErrStale) || !errors.Is(res[2].Err, domain.ErrInvalid) {
		t.Fatalf("an undeclared, an older and a future observation: %+v", res)
	}

	read := func() map[string]domain.Fact {
		var out map[string]domain.Fact
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = store.Subject(ctx, dbq.New(tx), org, "payments.charge", "ch_1", []string{"payments.charge.refundable"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if f, ok := read()["payments.charge.refundable"]; !ok || !f.Value.Bool || f.ProviderID != prov.ID {
		t.Fatalf("stored fact %+v", f)
	}
	if cat, _ := store.Catalog(ctx, org); cat["payments.charge.refundable"] != domain.TypeBoolean {
		t.Fatalf("catalog %v", cat)
	}
	if err := svc.DisableProvider(human, prov.ID); err != nil {
		t.Fatal(err)
	}
	if facts := read(); len(facts) != 0 {
		t.Fatalf("a disabled provider's facts still count: %v", facts)
	}
}
