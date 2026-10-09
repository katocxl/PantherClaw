// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// maxCompiled bounds the compiled-policy cache.
const maxCompiled = 128

// Reader implements pipeline.Reader over the module stores.
type Reader struct {
	Pool        *db.Pool
	Definitions *defpg.Store
	Policies    *polpg.Store
	FactStore   *factpg.Store
	Grants      *gpg.Store
	// Limits and Budget are the CEL limits and per-evaluation cost budget
	// (G0 M4 decision 4: server configuration).
	Limits celenv.Limits
	Budget uint64

	mu       sync.Mutex
	compiled map[string]*pipeline.Policy
}

var _ pipeline.Reader = (*Reader)(nil)

func notFound(err error) error {
	if errors.Is(err, gapp.ErrNotFound) || errors.Is(err, defpg.ErrNotFound) || db.IsNoRows(err) {
		return pipeline.ErrNotFound
	}
	return err
}

// Containment implements pipeline.Reader: the epoch, the kill switch and the
// database time. An org without a containment row cannot be decided for.
func (r *Reader) Containment(ctx context.Context, org ids.OrgID) (pipeline.Containment, error) {
	var out pipeline.Containment
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetContainmentNow(ctx, org)
		if err != nil {
			return fmt.Errorf("authority: containment: %w", err)
		}
		out = pipeline.Containment{Epoch: row.Epoch, KillSwitch: row.KillSwitch, Now: row.Now}
		return nil
	})
	return out, err
}

// Definition implements pipeline.Reader.
func (r *Reader) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	d, state, err := r.Definitions.Pinned(ctx, org, pin)
	if err != nil {
		return pipeline.Pinned{}, notFound(err)
	}
	return pipeline.Pinned{Definition: d, State: state}, nil
}

// Policy implements pipeline.Reader: the published bundle compiled against
// the org's fact catalog and active definitions, cached by all three.
func (r *Reader) Policy(ctx context.Context, org ids.OrgID) (*pipeline.Policy, error) {
	b, err := r.Policies.Published(ctx, org)
	if err != nil || b == nil {
		return nil, err
	}
	catalog, err := r.FactStore.Catalog(ctx, org)
	if err != nil {
		return nil, err
	}
	defs, err := r.Definitions.ActiveDefinitions(ctx, org)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|", org, b.ID, b.Version)
	for _, n := range slices.Sorted(maps.Keys(catalog)) {
		fmt.Fprintf(h, "%s=%s;", n, catalog[n])
	}
	for _, d := range defs {
		fmt.Fprintf(h, "%s;", d.Digest)
	}
	key := hex.EncodeToString(h.Sum(nil))
	r.mu.Lock()
	p, ok := r.compiled[key]
	r.mu.Unlock()
	if ok {
		return p, nil
	}
	c, err := (&papp.Engine{Limits: r.Limits, Facts: catalog}).Compile(b, defs)
	if err != nil {
		return nil, fmt.Errorf("authority: the published policy does not compile: %w", err)
	}
	budget := r.Budget
	if budget == 0 {
		budget = papp.DefaultBudget
	}
	p = &pipeline.Policy{Compiled: c, Version: fmt.Sprintf("%s@%d", b.ID, b.Version), Budget: budget}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.compiled == nil || len(r.compiled) >= maxCompiled {
		r.compiled = map[string]*pipeline.Policy{}
	}
	r.compiled[key] = p
	return p, nil
}

// Run implements pipeline.Reader.
func (r *Reader) Run(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	var out pipeline.Run
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).SubjectRun(ctx, org, id)
		if err != nil {
			return notFound(err)
		}
		out = pipeline.Run{
			AgentID: row.AgentID, EnvironmentID: row.EnvironmentID, Active: row.Live,
			Principal: principal(row.PrincipalUserID, row.PrincipalSaID, nil),
			Launcher:  principal(row.LauncherUserID, row.LauncherSaID, row.LauncherInstanceID),
		}
		if row.InstanceID != nil {
			out.InstanceID = *row.InstanceID
		}
		if row.GrantID != nil {
			out.GrantID, err = gdomain.ParseGrantID(row.GrantID.String())
		}
		return err
	})
	return out, err
}

func principal(user, sa, instance *ids.UUID) gdomain.Principal {
	switch {
	case user != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: *user}
	case sa != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: *sa}
	case instance != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: *instance}
	}
	return gdomain.Principal{}
}

// Agent implements pipeline.Reader.
func (r *Reader) Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	a, err := r.Grants.Agent(ctx, org, id)
	if err != nil {
		return pipeline.Agent{}, notFound(err)
	}
	return pipeline.Agent{State: a.State, BusinessUnitID: a.BusinessUnitID, TeamID: a.TeamID}, nil
}

// Chain implements pipeline.Reader.
func (r *Reader) Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	c, err := r.Grants.Chain(ctx, org, id)
	return c, notFound(err)
}

// Envelopes implements pipeline.Reader.
func (r *Reader) Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	return r.Grants.Envelopes(ctx, org, scopes)
}

// Facts implements pipeline.Reader.
func (r *Reader) Facts(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	var out map[string]fdomain.Fact
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = r.FactStore.Subject(ctx, dbq.New(tx), org, subjectType, subjectID, names)
		return err
	})
	return out, err
}

// Usage implements pipeline.Reader.
func (r *Reader) Usage(ctx context.Context, org ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	var out pipeline.Usage
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		acc, ctr, rows, err := pgbudgets.Usage(ctx, dbq.New(tx), org, plan.Budgets, plan.Counters)
		out = pipeline.Usage{Accounts: acc, Counters: ctr, CounterRows: rows}
		return err
	})
	if out.Accounts == nil {
		out.Accounts = map[bdomain.Ref]bdomain.Account{}
	}
	return out, err
}

// Claim implements pipeline.Reader.
func (r *Reader) Claim(ctx context.Context, org ids.OrgID, key string) (*pipeline.Claim, error) {
	var out *pipeline.Claim
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetDedupeClaim(ctx, org, key)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &pipeline.Claim{TransactionID: row.TransactionID, State: pipeline.ClaimState(row.State), At: row.ChangedAt}
		return nil
	})
	return out, err
}
