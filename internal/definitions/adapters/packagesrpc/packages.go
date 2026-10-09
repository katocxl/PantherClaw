// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package packagesrpc serves PackageService over Connect (HR-123, HR-124;
// G0 M4 part 2). Only packages listed in a targets document signed by a
// trusted package root are imported; activating is a separate, human-only
// step.
package packagesrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Packages serves PackageService.
type Packages struct {
	pantherclawv1connect.UnimplementedPackageServiceHandler
	svc *app.Admin
}

// New returns the PackageService handler.
func New(svc *app.Admin) *Packages { return &Packages{svc: svc} }

var (
	states = map[domain.State]pantherclawv1.PackageState{
		domain.StateUnclassified: pantherclawv1.PackageState_PACKAGE_STATE_UNCLASSIFIED,
		domain.StateDraft:        pantherclawv1.PackageState_PACKAGE_STATE_DRAFT,
		domain.StateReviewed:     pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED,
		domain.StateActive:       pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE,
		domain.StateStale:        pantherclawv1.PackageState_PACKAGE_STATE_STALE,
		domain.StateQuarantined:  pantherclawv1.PackageState_PACKAGE_STATE_QUARANTINED,
		domain.StateRetired:      pantherclawv1.PackageState_PACKAGE_STATE_RETIRED,
	}
	stateOf = func() map[pantherclawv1.PackageState]domain.State {
		out := map[pantherclawv1.PackageState]domain.State{}
		for k, v := range states {
			out[v] = k
		}
		return out
	}()
)

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// VersionProto renders an imported package version.
func VersionProto(v app.VersionInfo) *pantherclawv1.PackageVersion {
	out := &pantherclawv1.PackageVersion{
		Name: v.Name, Version: v.Version, State: states[v.State], FileDigest: v.FileDigest, Pinned: v.Pinned,
		ImportTime: ts(v.ImportedAt),
	}
	for _, d := range v.Definitions {
		out.Definitions = append(out.Definitions, &pantherclawv1.DefinitionRef{Operation: d.Operation, Digest: d.Digest})
	}
	return out
}

// ImportPackage implements PackageServiceHandler.
func (s *Packages) ImportPackage(ctx context.Context, req *pantherclawv1.ImportPackageRequest) (*pantherclawv1.ImportPackageResponse, error) {
	v, unchanged, err := s.svc.Import(ctx, req.GetName(), req.GetVersion(), req.GetTargets(), req.GetPackage())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ImportPackageResponse{Package: VersionProto(v), AlreadyImported: unchanged}, nil
}

// TransitionPackage implements PackageServiceHandler.
func (s *Packages) TransitionPackage(ctx context.Context, req *pantherclawv1.TransitionPackageRequest) (*pantherclawv1.TransitionPackageResponse, error) {
	v, err := s.svc.Transition(ctx, req.GetName(), req.GetVersion(), stateOf[req.GetState()])
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TransitionPackageResponse{Package: VersionProto(v)}, nil
}

// ListPackages implements PackageServiceHandler.
func (s *Packages) ListPackages(ctx context.Context, req *pantherclawv1.ListPackagesRequest) (*pantherclawv1.ListPackagesResponse, error) {
	vs, err := s.svc.List(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPackagesResponse{}
	for _, v := range vs {
		out.Packages = append(out.Packages, VersionProto(v))
	}
	return out, nil
}

// GetDefinition implements PackageServiceHandler.
func (s *Packages) GetDefinition(ctx context.Context, req *pantherclawv1.GetDefinitionRequest) (*pantherclawv1.GetDefinitionResponse, error) {
	d, err := s.svc.Definition(ctx, req.GetDigest())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetDefinitionResponse{
		Operation: d.Operation, Digest: d.Digest, Definition: d.Canonical, Package: d.Package, Version: d.Version,
		State: states[d.State],
	}, nil
}
