// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package waitlistrpc serves WaitlistService over Connect (reads only; M3
// has ADMISSION entries, decided through IdentityService and AgentService).
package waitlistrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// Waitlist serves WaitlistService.
type Waitlist struct {
	pantherclawv1connect.UnimplementedWaitlistServiceHandler
	r *app.Reader
}

// NewWaitlist returns the WaitlistService handler.
func NewWaitlist(r *app.Reader) *Waitlist { return &Waitlist{r: r} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

var stateToProto = map[string]pantherclawv1.WaitlistState{
	"OPEN":      pantherclawv1.WaitlistState_WAITLIST_STATE_OPEN,
	"APPROVED":  pantherclawv1.WaitlistState_WAITLIST_STATE_APPROVED,
	"REJECTED":  pantherclawv1.WaitlistState_WAITLIST_STATE_REJECTED,
	"EXPIRED":   pantherclawv1.WaitlistState_WAITLIST_STATE_EXPIRED,
	"CANCELLED": pantherclawv1.WaitlistState_WAITLIST_STATE_CANCELLED, //nolint:misspell // stored value
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func entryProto(e app.Entry) *pantherclawv1.WaitlistEntry {
	out := &pantherclawv1.WaitlistEntry{
		Id: e.ID.String(), Kind: pantherclawv1.WaitlistKind_WAITLIST_KIND_ADMISSION, SubjectType: e.SubjectType,
		SubjectId: e.SubjectID.String(), AgentId: e.AgentID.String(), State: stateToProto[e.State],
		Evidence: e.Evidence, UntrustedEvidence: e.Untrusted, DeadlineTime: ts(e.DeadlineAt), DecidedBy: e.DecidedBy,
		DecisionReason: e.DecisionReason, CreateTime: ts(e.CreatedAt),
	}
	if e.DecidedAt != nil {
		out.DecideTime = timestamppb.New(*e.DecidedAt)
	}
	return out
}

// ListWaitlistEntries implements WaitlistServiceHandler.
func (s *Waitlist) ListWaitlistEntries(ctx context.Context, req *pantherclawv1.ListWaitlistEntriesRequest) (*pantherclawv1.ListWaitlistEntriesResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var agent ids.UUID
	if req.AgentId != nil {
		if agent, err = parseID(req.GetAgentId()); err != nil {
			return nil, err
		}
	}
	var states []string
	for _, st := range req.GetStates() {
		for k, v := range stateToProto {
			if v == st {
				states = append(states, k)
			}
		}
	}
	p, err := s.r.List(ctx, pr, states, agent)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListWaitlistEntriesResponse{NextPageToken: p.Next}
	for _, e := range p.Items {
		out.Entries = append(out.Entries, entryProto(e))
	}
	return out, nil
}

// GetWaitlistEntry implements WaitlistServiceHandler.
func (s *Waitlist) GetWaitlistEntry(ctx context.Context, req *pantherclawv1.GetWaitlistEntryRequest) (*pantherclawv1.GetWaitlistEntryResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetWaitlistEntryResponse{Entry: entryProto(e)}, nil
}
