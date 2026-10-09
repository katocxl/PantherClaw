// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the definitions use cases: importing signed tool packages
// into an org and moving them through their lifecycle. Persistence is behind
// the Repository port; the tables arrive after M2 (migrations from 00020).
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrConflict reports that stored metadata, a pin or a lifecycle state
// changed between read and write (a lost race on a conditional update,
// HR-004). The caller may retry the whole use case.
var ErrConflict = errors.New("definitions: concurrent change")

// Record is everything one import writes, in one transaction.
type Record struct {
	// PreviousMetadata is the trusted metadata state that was read (nil if
	// none); Metadata replaces it only if it is unchanged.
	PreviousMetadata *trust.State
	Metadata         trust.State
	MetadataExpiry   time.Time
	// Package and Raw are the decoded and exact package bytes; FileDigest
	// is the digest the signed metadata lists.
	Package    *domain.Package
	Raw        []byte
	FileDigest string
	// PreviousPin is the org's pin that was read (nil if none); Pin replaces
	// it only if it is unchanged.
	PreviousPin *domain.Pin
	Pin         domain.Pin
	// State is the lifecycle state the new version starts in for the org.
	State domain.State
}

// Repository persists trusted metadata, package versions, pins and
// lifecycle states. Every write is conditional on the state that was read
// and returns ErrConflict when it changed.
type Repository interface {
	// TrustedMetadata returns the highest targets metadata the org has
	// accepted (anti-rollback is per org, so no table is global).
	TrustedMetadata(ctx context.Context, org ids.OrgID) (*trust.State, error)
	CurrentPin(ctx context.Context, org ids.OrgID, pkg string) (*domain.Pin, error)
	Import(ctx context.Context, org ids.OrgID, rec Record) error
	State(ctx context.Context, org ids.OrgID, pkg, version string) (domain.State, error)
	Transition(ctx context.Context, org ids.OrgID, pkg, version string, from, to domain.State) error
}

// Importer imports signed tool packages (HR-123).
type Importer struct {
	Roots trust.Roots
	Repo  Repository
	Clock clock.Clock
}

// Result describes an import.
type Result struct {
	Package   *domain.Package
	Pin       domain.Pin
	Unchanged bool
}

// Import verifies the targets document, checks that raw is exactly the
// signed file for name@version, decodes it, and advances the org's pin.
// Bytes are matched against the signed hash before they are parsed, so
// only signed bytes ever reach the YAML decoder. A new version starts
// REVIEWED: the publisher's signature is the review, and activation for the
// org is a separate, explicit step (F395).
func (im *Importer) Import(ctx context.Context, org ids.OrgID, name, version, targets string, raw []byte) (Result, error) {
	if org.IsZero() {
		return Result{}, fmt.Errorf("%w: org is required", domain.ErrInvalid)
	}
	v, err := trust.Verify(targets, im.Roots, im.Clock.Now())
	if err != nil {
		return Result{}, err
	}
	last, err := im.Repo.TrustedMetadata(ctx, org)
	if err != nil {
		return Result{}, err
	}
	if err := trust.CheckAdvance(last, v); err != nil {
		return Result{}, err
	}
	digest, err := v.Match(name, version, raw)
	if err != nil {
		return Result{}, err
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		return Result{}, err
	}
	if p.Name != name || p.Version != version {
		return Result{}, fmt.Errorf("%w: file declares %s, signed as %s", trust.ErrUntrusted, trust.Key(p.Name, p.Version), trust.Key(name, version))
	}
	pin := domain.Pin{Package: name, Version: version, Digest: digest}
	cur, err := im.Repo.CurrentPin(ctx, org, name)
	if err != nil {
		return Result{}, err
	}
	if err := domain.CheckPinAdvance(cur, pin); err != nil {
		return Result{}, err
	}
	if cur != nil && *cur == pin {
		return Result{Package: p, Pin: pin, Unchanged: true}, nil
	}
	err = im.Repo.Import(ctx, org, Record{
		PreviousMetadata: last, Metadata: trust.State{Version: v.Version, PayloadDigest: v.PayloadDigest},
		MetadataExpiry: v.Expiry, Package: p, Raw: raw, FileDigest: digest,
		PreviousPin: cur, Pin: pin, State: domain.StateReviewed,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Package: p, Pin: pin}, nil
}

// Transition moves an org's package version through the lifecycle (for
// example REVIEWED → ACTIVE to activate it, ACTIVE → QUARANTINED on a
// behavior mismatch). Illegal transitions are refused before any write.
func (im *Importer) Transition(ctx context.Context, org ids.OrgID, pkg, version string, to domain.State) error {
	from, err := im.Repo.State(ctx, org, pkg, version)
	if err != nil {
		return err
	}
	if err := domain.Lifecycle.Check(from, to); err != nil {
		return err
	}
	return im.Repo.Transition(ctx, org, pkg, version, from, to)
}
