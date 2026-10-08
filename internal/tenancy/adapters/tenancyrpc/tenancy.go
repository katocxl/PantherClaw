// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package tenancyrpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Tenancy serves TenancyService.
type Tenancy struct {
	pantherclawv1connect.UnimplementedTenancyServiceHandler
	h *app.Hierarchy
}

// NewTenancy returns the TenancyService handler.
func NewTenancy(h *app.Hierarchy) *Tenancy { return &Tenancy{h: h} }

// GetOrg implements TenancyServiceHandler.
func (s *Tenancy) GetOrg(ctx context.Context, _ *pantherclawv1.GetOrgRequest) (*pantherclawv1.GetOrgResponse, error) {
	o, err := s.h.GetOrg(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetOrgResponse{Org: orgProto(o)}, nil
}

// UpdateOrg implements TenancyServiceHandler.
func (s *Tenancy) UpdateOrg(ctx context.Context, req *pantherclawv1.UpdateOrgRequest) (*pantherclawv1.UpdateOrgResponse, error) {
	o, err := s.h.UpdateOrg(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateOrgResponse{Org: orgProto(o)}, nil
}

// CreateBusinessUnit implements TenancyServiceHandler.
func (s *Tenancy) CreateBusinessUnit(ctx context.Context, req *pantherclawv1.CreateBusinessUnitRequest) (*pantherclawv1.CreateBusinessUnitResponse, error) {
	b, err := s.h.CreateBusinessUnit(ctx, app.NewEntity{Slug: req.GetSlug(), Name: req.GetName(), Description: req.GetDescription()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateBusinessUnitResponse{BusinessUnit: businessUnitProto(b)}, nil
}

// GetBusinessUnit implements TenancyServiceHandler.
func (s *Tenancy) GetBusinessUnit(ctx context.Context, req *pantherclawv1.GetBusinessUnitRequest) (*pantherclawv1.GetBusinessUnitResponse, error) {
	id, err := parseID[td.BusinessUnit](req.GetId())
	if err != nil {
		return nil, err
	}
	b, err := s.h.GetBusinessUnit(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetBusinessUnitResponse{BusinessUnit: businessUnitProto(b)}, nil
}

// ListBusinessUnits implements TenancyServiceHandler.
func (s *Tenancy) ListBusinessUnits(ctx context.Context, req *pantherclawv1.ListBusinessUnitsRequest) (*pantherclawv1.ListBusinessUnitsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.h.ListBusinessUnits(ctx, pr, req.GetIncludeArchived())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBusinessUnitsResponse{NextPageToken: p.Next}
	for _, b := range p.Items {
		out.BusinessUnits = append(out.BusinessUnits, businessUnitProto(b))
	}
	return out, nil
}

// UpdateBusinessUnit implements TenancyServiceHandler.
func (s *Tenancy) UpdateBusinessUnit(ctx context.Context, req *pantherclawv1.UpdateBusinessUnitRequest) (*pantherclawv1.UpdateBusinessUnitResponse, error) {
	id, err := parseID[td.BusinessUnit](req.GetId())
	if err != nil {
		return nil, err
	}
	b, err := s.h.UpdateBusinessUnit(ctx, id, req.Name, req.Description)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateBusinessUnitResponse{BusinessUnit: businessUnitProto(b)}, nil
}

// ArchiveBusinessUnit implements TenancyServiceHandler.
func (s *Tenancy) ArchiveBusinessUnit(ctx context.Context, req *pantherclawv1.ArchiveBusinessUnitRequest) (*pantherclawv1.ArchiveBusinessUnitResponse, error) {
	id, err := parseID[td.BusinessUnit](req.GetId())
	if err != nil {
		return nil, err
	}
	b, err := s.h.ArchiveBusinessUnit(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ArchiveBusinessUnitResponse{BusinessUnit: businessUnitProto(b)}, nil
}

// CreateTeam implements TenancyServiceHandler.
func (s *Tenancy) CreateTeam(ctx context.Context, req *pantherclawv1.CreateTeamRequest) (*pantherclawv1.CreateTeamResponse, error) {
	bu, err := parseOptID[td.BusinessUnit](req.GetBusinessUnitId())
	if err != nil {
		return nil, err
	}
	t, err := s.h.CreateTeam(ctx, bu, app.NewEntity{Slug: req.GetSlug(), Name: req.GetName(), Description: req.GetDescription()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateTeamResponse{Team: teamProto(t)}, nil
}

// GetTeam implements TenancyServiceHandler.
func (s *Tenancy) GetTeam(ctx context.Context, req *pantherclawv1.GetTeamRequest) (*pantherclawv1.GetTeamResponse, error) {
	id, err := parseID[td.Team](req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := s.h.GetTeam(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetTeamResponse{Team: teamProto(t)}, nil
}

// ListTeams implements TenancyServiceHandler.
func (s *Tenancy) ListTeams(ctx context.Context, req *pantherclawv1.ListTeamsRequest) (*pantherclawv1.ListTeamsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	bu, err := parseOptID[td.BusinessUnit](req.GetBusinessUnitId())
	if err != nil {
		return nil, err
	}
	p, err := s.h.ListTeams(ctx, pr, bu, req.GetIncludeArchived())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTeamsResponse{NextPageToken: p.Next}
	for _, t := range p.Items {
		out.Teams = append(out.Teams, teamProto(t))
	}
	return out, nil
}

// UpdateTeam implements TenancyServiceHandler.
func (s *Tenancy) UpdateTeam(ctx context.Context, req *pantherclawv1.UpdateTeamRequest) (*pantherclawv1.UpdateTeamResponse, error) {
	id, err := parseID[td.Team](req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := s.h.UpdateTeam(ctx, id, req.Name, req.Description)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateTeamResponse{Team: teamProto(t)}, nil
}

// ArchiveTeam implements TenancyServiceHandler.
func (s *Tenancy) ArchiveTeam(ctx context.Context, req *pantherclawv1.ArchiveTeamRequest) (*pantherclawv1.ArchiveTeamResponse, error) {
	id, err := parseID[td.Team](req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := s.h.ArchiveTeam(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ArchiveTeamResponse{Team: teamProto(t)}, nil
}

// AddTeamMember implements TenancyServiceHandler.
func (s *Tenancy) AddTeamMember(ctx context.Context, req *pantherclawv1.AddTeamMemberRequest) (*pantherclawv1.AddTeamMemberResponse, error) {
	team, err := parseID[td.Team](req.GetTeamId())
	if err != nil {
		return nil, err
	}
	user, err := parseID[td.User](req.GetUserId())
	if err != nil {
		return nil, err
	}
	m, err := s.h.AddTeamMember(ctx, team, user)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddTeamMemberResponse{Member: memberProto(m)}, nil
}

// RemoveTeamMember implements TenancyServiceHandler.
func (s *Tenancy) RemoveTeamMember(ctx context.Context, req *pantherclawv1.RemoveTeamMemberRequest) (*pantherclawv1.RemoveTeamMemberResponse, error) {
	team, err := parseID[td.Team](req.GetTeamId())
	if err != nil {
		return nil, err
	}
	user, err := parseID[td.User](req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.h.RemoveTeamMember(ctx, team, user); err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveTeamMemberResponse{}, nil
}

// ListTeamMembers implements TenancyServiceHandler.
func (s *Tenancy) ListTeamMembers(ctx context.Context, req *pantherclawv1.ListTeamMembersRequest) (*pantherclawv1.ListTeamMembersResponse, error) {
	team, err := parseID[td.Team](req.GetTeamId())
	if err != nil {
		return nil, err
	}
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.h.ListTeamMembers(ctx, team, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTeamMembersResponse{NextPageToken: p.Next}
	for _, m := range p.Items {
		out.Members = append(out.Members, memberProto(m))
	}
	return out, nil
}

// CreateEnvironment implements TenancyServiceHandler.
func (s *Tenancy) CreateEnvironment(ctx context.Context, req *pantherclawv1.CreateEnvironmentRequest) (*pantherclawv1.CreateEnvironmentResponse, error) {
	team, err := parseOptID[td.Team](req.GetTeamId())
	if err != nil {
		return nil, err
	}
	e, err := s.h.CreateEnvironment(ctx, team, envKindFromProto[req.GetKind()],
		app.NewEntity{Slug: req.GetSlug(), Name: req.GetName(), Description: req.GetDescription()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEnvironmentResponse{Environment: environmentProto(e)}, nil
}

// GetEnvironment implements TenancyServiceHandler.
func (s *Tenancy) GetEnvironment(ctx context.Context, req *pantherclawv1.GetEnvironmentRequest) (*pantherclawv1.GetEnvironmentResponse, error) {
	id, err := parseID[td.Environment](req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.h.GetEnvironment(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEnvironmentResponse{Environment: environmentProto(e)}, nil
}

// ListEnvironments implements TenancyServiceHandler.
func (s *Tenancy) ListEnvironments(ctx context.Context, req *pantherclawv1.ListEnvironmentsRequest) (*pantherclawv1.ListEnvironmentsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	team, err := parseOptID[td.Team](req.GetTeamId())
	if err != nil {
		return nil, err
	}
	p, err := s.h.ListEnvironments(ctx, pr, team, req.GetIncludeArchived())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListEnvironmentsResponse{NextPageToken: p.Next}
	for _, e := range p.Items {
		out.Environments = append(out.Environments, environmentProto(e))
	}
	return out, nil
}

// UpdateEnvironment implements TenancyServiceHandler.
func (s *Tenancy) UpdateEnvironment(ctx context.Context, req *pantherclawv1.UpdateEnvironmentRequest) (*pantherclawv1.UpdateEnvironmentResponse, error) {
	id, err := parseID[td.Environment](req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.h.UpdateEnvironment(ctx, id, req.Name, req.Description)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateEnvironmentResponse{Environment: environmentProto(e)}, nil
}

// ArchiveEnvironment implements TenancyServiceHandler.
func (s *Tenancy) ArchiveEnvironment(ctx context.Context, req *pantherclawv1.ArchiveEnvironmentRequest) (*pantherclawv1.ArchiveEnvironmentResponse, error) {
	id, err := parseID[td.Environment](req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.h.ArchiveEnvironment(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ArchiveEnvironmentResponse{Environment: environmentProto(e)}, nil
}
