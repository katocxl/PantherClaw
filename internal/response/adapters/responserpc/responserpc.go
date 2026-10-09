// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package responserpc serves ContainmentService (G0 M6). It only reads: the
// kill switch is engaged and restored on the emergency-stop page, never
// through the API (HR-113, decision 2).
package responserpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
)

// Handler serves ContainmentService.
type Handler struct {
	pantherclawv1connect.UnimplementedContainmentServiceHandler
	s *rapp.Service
}

// New returns the ContainmentService handler.
func New(s *rapp.Service) *Handler { return &Handler{s: s} }

var _ pantherclawv1connect.ContainmentServiceHandler = (*Handler)(nil)

// GetKillSwitch implements ContainmentServiceHandler.
func (h *Handler) GetKillSwitch(ctx context.Context, _ *pantherclawv1.GetKillSwitchRequest) (*pantherclawv1.GetKillSwitchResponse, error) {
	st, err := h.s.Status(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetKillSwitchResponse{
		Engaged: st.Engaged, Epoch: st.Epoch, EngagedBy: st.EngagedBy, Reason: st.Reason, PageUrl: st.PageURL,
	}
	if st.EngagedAt != nil {
		out.EngageTime = timestamppb.New(*st.EngagedAt)
	}
	if p := st.Pending; p != nil {
		out.PendingRestore = &pantherclawv1.KillSwitchRestore{
			Id: p.ID.String(), ProposedBy: p.ProposedBy.String(), ProposeTime: timestamppb.New(p.CreatedAt),
			ExpireTime: timestamppb.New(p.ExpiresAt), Reason: p.Reason,
		}
	}
	return out, nil
}
