// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// Development fact provider: the refund definition needs a fresh
// payments.charge.refundable fact about the charge (a prerequisite).
const (
	devFact          = "payments.charge.refundable"
	devFactSubject   = "payments.charge"
	devGrantLifetime = 24 * time.Hour
)

// seedPackage imports the reference payments package into org and activates
// it. It is signed with a throwaway development root generated here and
// trusted for this import only (G0 M4 part 2, decision 3): the org records
// the signed metadata, never the key, and no server trusts that key.
func seedPackage(ctx context.Context, pool *db.Pool, org ids.OrgID) error {
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		return err
	}
	signer, err := jws.NewSigner(kid, priv)
	if err != nil {
		return err
	}
	raw := mockpayments.Package
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(180 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{
			trust.Key(mockpayments.Name, mockpayments.Version): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
		},
	}, signer)
	if err != nil {
		return err
	}
	im := &defsapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: &defspg.Store{Pool: pool}, Clock: clock.System{}}
	ev := &audit.Event{
		Name: "package.imported", Actor: devSeedActor, Outcome: audit.Success,
		Object: &audit.Object{Type: "package_version", ID: trust.Key(mockpayments.Name, mockpayments.Version)},
	}
	if _, err := im.Import(ctx, org, mockpayments.Name, mockpayments.Version, doc, raw, ev); err != nil {
		return fmt.Errorf("dev seed: package: %w", err)
	}
	act := &audit.Event{
		Name: "package.transitioned", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "package_version", ID: trust.Key(mockpayments.Name, mockpayments.Version)},
		Details: map[string]string{"from": string(defs.StateReviewed), "to": string(defs.StateActive)},
	}
	if err := im.Transition(ctx, org, mockpayments.Name, mockpayments.Version, defs.StateActive, act); err != nil {
		return fmt.Errorf("dev seed: activate package: %w", err)
	}
	return nil
}

// seedFacts registers a development fact provider for refundable charges,
// bound to a new service account, and returns an API key that lets it
// report facts (fact.write only).
func seedFacts(ctx context.Context, pool *db.Pool, org ids.OrgID, env credential.Env) (credential.Token, error) {
	sa := ids.NewV7()
	key, err := credential.New(credential.APIKey, env, org)
	if err != nil {
		return key, err
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.InsertServiceAccount(ctx, dbq.InsertServiceAccountParams{
			OrgID: org, ID: sa, Name: "dev-billing", Description: "development fact provider (dev seed)", CreatedBy: "dev-seed",
		}); err != nil {
			return err
		}
		if _, err := q.InsertRoleBinding(ctx, dbq.InsertRoleBindingParams{
			OrgID: org, ID: ids.NewV7(), Role: "fact_provider", ServiceAccountID: &sa, ScopeType: "ORG", CreatedBy: "dev-seed",
		}); err != nil {
			return err
		}
		_, err := q.InsertAPIKey(ctx, dbq.InsertAPIKeyParams{
			OrgID: org, ID: ids.NewV7(), ServiceAccountID: sa, Name: "dev-facts", SecretHash: key.Hash(), Hint: key.Hint(),
			Scopes: []string{"fact.write"}, CreatedBy: "dev-seed", TtlDays: 30,
		})
		return err
	})
	if err != nil {
		return key, fmt.Errorf("dev seed: fact provider account: %w", err)
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: "dev.billing", ServiceAccountID: sa, State: fdomain.ProviderActive,
		Facts: []fdomain.Declaration{{Name: devFact, Type: fdomain.TypeBoolean, SubjectType: devFactSubject, MaxLag: 5 * time.Minute}},
	}
	if err := p.Validate(func(string) bool { return false }); err != nil {
		return key, err
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object: &audit.Object{Type: "fact_provider", ID: p.ID.String()}, Details: map[string]string{"service_account": sa.String()},
	}
	if err := (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "operator:dev-seed", ev); err != nil {
		return key, fmt.Errorf("dev seed: fact provider: %w", err)
	}
	return key, nil
}

// devGrantTerms are the terms of the grant dev seed issues.
type devGrantTerms struct {
	MaxPerAction money.Money // per refund
	Limit        money.Money // the task budget
	MaxCount     int         // 0: no count limit
}

// seedGrant issues a root grant to the seeded agent for its owner: refunds
// up to the per-action maximum, a task budget, and one level of
// delegation. It is checked like any issuance against the org's active
// definitions; dev seed is the grantor of record (no person signs in for
// the seeded owner).
func seedGrant(ctx context.Context, pool *db.Pool, org ids.OrgID, w devWorkload, t devGrantTerms) (gdomain.Grant, error) {
	bounds, err := json.Marshal(map[string]any{
		"operations": []string{"payments.refund.create", "payments.refund.get"},
		"params": map[string]any{"payments.refund.create": map[string]any{
			"amount": map[string]any{"max": map[string]string{string(t.MaxPerAction.Currency): t.MaxPerAction.Amount.String()}},
		}},
	})
	if err != nil {
		return gdomain.Grant{}, err
	}
	budget := map[string]any{
		"id": "task", "grouping": "task", "operations": []string{"payments.refund.create"},
		"currency": string(t.Limit.Currency), "limit": t.Limit.Amount.String(), "period": "none",
	}
	if t.MaxCount > 0 {
		budget["max_count"] = fmt.Sprint(t.MaxCount)
	}
	limits, err := json.Marshal(map[string]any{"budgets": []any{budget}})
	if err != nil {
		return gdomain.Grant{}, err
	}
	b, err := gdomain.DecodeBounds(bounds)
	if err != nil {
		return gdomain.Grant{}, err
	}
	lim, err := gdomain.DecodeLimits(limits)
	if err != nil {
		return gdomain.Grant{}, err
	}
	now := time.Now()
	g := gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: org, Revision: 1, State: gdomain.StateActive,
		AgentID: w.Agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.Owner}, EnvironmentID: w.Env,
		TaskRef: "dev seed", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(devGrantLifetime), Bounds: b, Limits: lim,
		Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Grantor:    gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.Owner}, Basis: "issued by pantherclaw-server dev seed",
	}
	defsStore := &defspg.Store{Pool: pool}
	refund, err := defsStore.Active(ctx, org, "payments.refund.create")
	if err != nil {
		return gdomain.Grant{}, err
	}
	lookup := func(op string) *defs.Definition {
		if op == "payments.refund.create" {
			return refund
		}
		return nil
	}
	if err := g.ValidateIssue(gdomain.IssueContext{Now: now, Lookup: lookup}); err != nil {
		return gdomain.Grant{}, fmt.Errorf("dev seed: grant: %w", err)
	}
	ev := audit.Event{
		Name: "grant.issued", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "grant", ID: g.ID.String()},
		Details: map[string]string{"agent": w.Agent.String(), "principal": g.Principal.String()},
	}
	if err := (&grantspg.Store{Pool: pool}).Issue(ctx, org, g, ev); err != nil {
		return gdomain.Grant{}, fmt.Errorf("dev seed: grant: %w", err)
	}
	return g, nil
}

// writeSecretFile writes s to a new 0600 file (never overwritten).
func writeSecretFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, s+"\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
