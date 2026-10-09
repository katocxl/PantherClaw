// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgstore stores policy bundles per org in PostgreSQL: immutable
// versions, at most one published per org (the policy/app BundleStore port,
// part 1; G0 M4 part 2, design decision 20).
package pgstore

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Errors.
var (
	ErrNotFound = errors.New("policy: version not found")
	// ErrNotDraft reports a publication of a version that is not a draft
	// (a lost race or a repeat, HR-004).
	ErrNotDraft = errors.New("policy: only a draft can be published")
)

// MaxBundleBytes is the largest stored bundle.
const MaxBundleBytes = 4 << 20

// Store implements app.BundleStore.
type Store struct {
	Pool *db.Pool
}

var _ app.BundleStore = (*Store)(nil)

// Version is one stored bundle version.
type Version struct {
	ID          ids.UUID
	BundleID    string
	Version     int
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	PublishedAt *time.Time
}

// Published implements app.BundleStore: the org's published bundle, or nil.
func (s *Store) Published(ctx context.Context, org ids.OrgID) (*domain.Bundle, error) {
	var out *domain.Bundle
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPublishedPolicy(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out, err = decode(row.Bundle)
		return err
	})
	return out, err
}

// CreateVersion stores a bundle as the next draft version of its policy
// and returns the version id and number. The stored bundle carries that
// number, whatever the caller set.
func (s *Store) CreateVersion(ctx context.Context, org ids.OrgID, b *domain.Bundle, createdBy string) (ids.UUID, int, error) {
	id := ids.NewV7()
	var version int
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		policyID, err := q.GetPolicyID(ctx, org, b.ID)
		if db.IsNoRows(err) {
			policyID = ids.NewV7()
			err = q.InsertPolicy(ctx, org, policyID, b.ID)
		}
		if err != nil {
			return err
		}
		next, err := q.NextPolicyVersion(ctx, org, policyID)
		if err != nil {
			return err
		}
		stored := *b
		stored.Version, version = int(next), int(next)
		if err := stored.Validate(); err != nil {
			return err
		}
		raw, err := json.Marshal(stored, json.Deterministic(true))
		if err != nil {
			return err
		}
		if len(raw) > MaxBundleBytes {
			return fmt.Errorf("%w: the bundle is larger than %d bytes", domain.ErrInvalid, MaxBundleBytes)
		}
		return q.InsertPolicyVersion(ctx, dbq.InsertPolicyVersionParams{
			OrgID: org, ID: id, PolicyID: policyID, Version: next, Bundle: raw, CreatedBy: createdBy,
		})
	})
	return id, version, err
}

// Get returns a stored version's bundle and state.
func (s *Store) Get(ctx context.Context, org ids.OrgID, id ids.UUID) (*domain.Bundle, string, error) {
	var out *domain.Bundle
	var state string
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPolicyVersion(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		state = row.State
		out, err = decode(row.Bundle)
		return err
	})
	return out, state, err
}

// Publish makes a draft the org's published version, superseding the
// previous one in the same transaction.
func (s *Store) Publish(ctx context.Context, org ids.OrgID, id ids.UUID, publishedBy string) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.SupersedePublishedPolicy(ctx, org, id); err != nil {
			return err
		}
		return db.ExpectOneRow(q.PublishPolicyVersion(ctx, &publishedBy, org, id))
	})
	if errors.Is(err, db.ErrLostRace) {
		return ErrNotDraft
	}
	return err
}

// List returns the org's versions, newest first.
func (s *Store) List(ctx context.Context, org ids.OrgID, limit int) ([]Version, error) {
	var out []Version
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPolicyVersions(ctx, org, int32(min(max(limit, 1), 200)))
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, Version{
				ID: r.ID, BundleID: r.BundleID, Version: int(r.Version), State: r.State,
				CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt,
			})
		}
		return nil
	})
	return out, err
}

func decode(raw []byte) (*domain.Bundle, error) {
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("policy: stored bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("policy: stored bundle: %w", err)
	}
	return &b, nil
}
