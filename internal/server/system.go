// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// systemService implements SystemService (public, non-sensitive).
type systemService struct {
	pantherclawv1connect.UnimplementedSystemServiceHandler
}

// GetBuildInfo returns the build identity.
func (systemService) GetBuildInfo(_ context.Context, req *pantherclawv1.GetBuildInfoRequest) (*pantherclawv1.GetBuildInfoResponse, error) {
	v := version.Get()
	return &pantherclawv1.GetBuildInfoResponse{
		Version: v.Version, Commit: v.Commit, Fips: v.FIPS, ClientRequestId: req.GetClientRequestId(),
	}, nil
}
