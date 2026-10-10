// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Circuits records a gateway's circuit reports (connections app).
type Circuits interface {
	OpenCircuit(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, unknown, total int32) (bool, error)
}

// WithCircuits serves ReportCircuit from c.
func (h *GatewayHandler) WithCircuits(c Circuits) *GatewayHandler {
	h.circuits = c
	return h
}

// ReportCircuit implements GatewayServiceHandler, on the mTLS listener
// only (gateway.observe): the calling gateway's breaker opened for one of
// its connections, which the server quarantines (HR-078). The org and the
// gateway come from the certificate alone.
func (h *GatewayHandler) ReportCircuit(ctx context.Context, req *pb.ReportCircuitRequest) (*pb.ReportCircuitResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.circuits == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "circuit reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	quarantined, err := h.circuits.OpenCircuit(ctx, id.Org, id.Gateway, conn, req.GetUnknownCount(), req.GetTotalCount())
	if err != nil {
		return nil, err
	}
	return &pb.ReportCircuitResponse{Quarantined: quarantined}, nil
}
