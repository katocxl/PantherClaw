// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions of the package use cases (the tenancy catalog's).
const (
	PermPackageRead     = tdomain.PermPackageRead
	PermPackageImport   = tdomain.PermPackageImport
	PermPackageActivate = tdomain.PermPackageActivate // human only
)

// API errors.
var (
	ErrNotFound          = pcerr.New(pcerr.NotFound, "PACKAGE_NOT_FOUND", "package version or definition not found")
	ErrHumanOnly         = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrRevisionChanged   = pcerr.New(pcerr.Aborted, "PACKAGE_CHANGED", "the package changed meanwhile; read it again")
	errIllegalTransition = pcerr.New(pcerr.FailedPrecondition, "TRANSITION_NOT_ALLOWED", "the package cannot move to that state from its current one")
)

// VersionInfo is one imported package version.
type VersionInfo struct {
	Name, Version string
	State         domain.State
	FileDigest    string
	Definitions   []DefinitionRef
	Pinned        bool
	ImportedAt    time.Time
}

// DefinitionRef names one definition of a version.
type DefinitionRef struct{ Operation, Digest string }

// DefinitionInfo is a stored definition and the newest version holding it.
type DefinitionInfo struct {
	Operation, Digest string
	Canonical         []byte
	Package, Version  string
	State             domain.State
}

// Reads lists what an org imported (the API's view; the pipeline reads
// definitions through its own port).
type Reads interface {
	// ListVersions lists versions, of every package when name is empty.
	ListVersions(ctx context.Context, org ids.OrgID, name string) ([]VersionInfo, error)
	// DefinitionByDigest returns ErrNotFound when the org has no
	// definition with that digest.
	DefinitionByDigest(ctx context.Context, org ids.OrgID, digest string) (DefinitionInfo, error)
}

// Authorizer checks a caller's permission at a path.
type Authorizer interface {
	Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error
}

// Admin runs the package use cases of the API: the caller's permission at
// the org, then the Importer. Importing and activating are separate steps,
// and activating is human only (F395).
type Admin struct {
	Importer *Importer
	Reads    Reads
	Authz    Authorizer
	// Ents decides whether the org may use its own package-signing keys
	// (HR-162); without it, org-signed packages are refused.
	Ents Entitlements
}

// apiError maps import and lifecycle errors to API errors. The messages
// describe the request (signatures, digests, versions), never another
// org's data.
func apiError(err error) error {
	for _, m := range []struct {
		sentinel error
		code     pcerr.Code
		name     string
	}{
		{trust.ErrExpired, pcerr.FailedPrecondition, "PACKAGE_METADATA_EXPIRED"},
		{trust.ErrRollback, pcerr.FailedPrecondition, "PACKAGE_METADATA_ROLLBACK"},
		{trust.ErrUntrusted, pcerr.FailedPrecondition, "PACKAGE_UNTRUSTED"},
		{domain.ErrPinRollback, pcerr.FailedPrecondition, "PACKAGE_PIN_ROLLBACK"},
		{domain.ErrPinConflict, pcerr.FailedPrecondition, "PACKAGE_PIN_CONFLICT"},
		{ErrOperationTaken, pcerr.FailedPrecondition, "PACKAGE_OPERATION_TAKEN"},
		{ErrKeyCompromised, pcerr.FailedPrecondition, "PACKAGE_KEY_COMPROMISED"},
		{manifest.ErrInvalid, pcerr.InvalidArgument, "PACKAGE_INVALID"},
		{domain.ErrInvalid, pcerr.InvalidArgument, "PACKAGE_INVALID"},
	} {
		if errors.Is(err, m.sentinel) {
			return pcerr.Wrap(err, m.code, m.name, strings.TrimPrefix(err.Error(), m.sentinel.Error()+": "))
		}
	}
	switch {
	case errors.Is(err, ErrConflict):
		return ErrRevisionChanged
	case errors.Is(err, statemachine.ErrIllegalTransition):
		return errIllegalTransition
	}
	return err
}

func (a *Admin) caller(ctx context.Context, p tdomain.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return tapp.Caller{}, err
	}
	return c, a.Authz.Require(c, p, tdomain.OrgPath(c.Org))
}

// Import verifies and stores one package version (package.import at the
// org). It starts REVIEWED and decides nothing until activated.
func (a *Admin) Import(ctx context.Context, name, version, targets string, raw []byte) (VersionInfo, bool, error) {
	c, err := a.caller(ctx, PermPackageImport)
	if err != nil {
		return VersionInfo{}, false, err
	}
	// Only routing: the importer verifies an org kid against the org's
	// keys alone, so a forged kid cannot skip this check.
	if kid, _, err := jws.Unverified(strings.TrimSpace(targets)); err == nil && trust.IsOrgKID(kid) {
		if err := a.entitled(ctx); err != nil {
			return VersionInfo{}, false, err
		}
	}
	ev := &audit.Event{
		Name: "package.imported", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "package_version", ID: trust.Key(name, version)},
	}
	res, err := a.Importer.Import(ctx, c.Org, name, version, targets, raw, ev)
	if err != nil {
		return VersionInfo{}, false, apiError(err)
	}
	v, err := a.version(ctx, c.Org, name, version)
	return v, res.Unchanged, err
}

// Transition moves a package version through its lifecycle
// (package.activate at the org, human only). Quarantining or retiring one
// invalidates permits already issued (the repository raises the epoch).
func (a *Admin) Transition(ctx context.Context, name, version string, to domain.State) (VersionInfo, error) {
	c, err := a.caller(ctx, PermPackageActivate)
	if err != nil {
		return VersionInfo{}, err
	}
	if !c.Human() {
		return VersionInfo{}, ErrHumanOnly
	}
	from, err := a.Importer.Repo.State(ctx, c.Org, name, version)
	if err != nil {
		return VersionInfo{}, notFound(err)
	}
	ev := &audit.Event{
		Name: "package.transitioned", Actor: c.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "package_version", ID: trust.Key(name, version)},
		Details: map[string]string{"from": string(from), "to": string(to)},
	}
	if err := a.Importer.Transition(ctx, c.Org, name, version, to, ev); err != nil {
		return VersionInfo{}, apiError(notFound(err))
	}
	return a.version(ctx, c.Org, name, version)
}

// List lists imported package versions (package.read at the org).
func (a *Admin) List(ctx context.Context, name string) ([]VersionInfo, error) {
	c, err := a.caller(ctx, PermPackageRead)
	if err != nil {
		return nil, err
	}
	return a.Reads.ListVersions(ctx, c.Org, name)
}

// Definition returns one definition by digest (package.read at the org).
func (a *Admin) Definition(ctx context.Context, digest string) (DefinitionInfo, error) {
	c, err := a.caller(ctx, PermPackageRead)
	if err != nil {
		return DefinitionInfo{}, err
	}
	d, err := a.Reads.DefinitionByDigest(ctx, c.Org, digest)
	return d, notFound(err)
}

func (a *Admin) version(ctx context.Context, org ids.OrgID, name, version string) (VersionInfo, error) {
	vs, err := a.Reads.ListVersions(ctx, org, name)
	if err != nil {
		return VersionInfo{}, err
	}
	for _, v := range vs {
		if v.Version == version {
			return v, nil
		}
	}
	return VersionInfo{}, ErrNotFound
}

func notFound(err error) error {
	if errors.Is(err, ErrMissing) {
		return ErrNotFound
	}
	return err
}
