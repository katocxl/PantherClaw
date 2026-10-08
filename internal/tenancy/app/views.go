// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Org is the caller's organization.
type Org struct {
	ID        ids.OrgID
	Name      string
	CreatedAt time.Time
}

// BusinessUnit is a business unit.
type BusinessUnit struct {
	ID                   domain.BusinessUnitID
	Slug, Name           string
	Description          string
	State                domain.State
	CreatedAt, UpdatedAt time.Time
}

// Team is a team. BusinessUnit is zero for a team directly under the org.
type Team struct {
	ID                   domain.TeamID
	BusinessUnit         domain.BusinessUnitID
	Slug, Name           string
	Description          string
	State                domain.State
	CreatedAt, UpdatedAt time.Time
}

// Environment is an environment. Team is zero for an org-level environment.
type Environment struct {
	ID                   domain.EnvironmentID
	Team                 domain.TeamID
	Slug, Name           string
	Description          string
	Kind                 domain.EnvironmentKind
	State                domain.State
	CreatedAt, UpdatedAt time.Time
}

// TeamMember is a user's membership of a team.
type TeamMember struct {
	User               domain.UserID
	Email, DisplayName string
	AddedAt            time.Time
}

// Page is one page of a list.
type Page[T any] struct {
	Items []T
	Next  string
}

// idOf converts an id read from the database. Every stored id was minted as
// UUIDv7 by this code; an id that is not converts to the zero ID.
func idOf[K ids.Kind](u ids.UUID) ids.ID[K] {
	id, _ := ids.FromUUID[K](u)
	return id
}

func optID[K ids.Kind](u *ids.UUID) ids.ID[K] {
	if u == nil {
		return ids.ID[K]{}
	}
	return idOf[K](*u)
}

func optUUID[K ids.Kind](id ids.ID[K]) *ids.UUID {
	if id.IsZero() {
		return nil
	}
	u := id.UUID()
	return &u
}

func orgView(r dbq.PcOrg) Org { return Org{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt} }

func businessUnitView(r dbq.PcBusinessUnit) BusinessUnit {
	return BusinessUnit{
		ID: idOf[domain.BusinessUnit](r.ID), Slug: r.Slug, Name: r.Name, Description: r.Description,
		State: domain.State(r.State), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func teamView(r dbq.PcTeam) Team {
	return Team{
		ID: idOf[domain.Team](r.ID), BusinessUnit: optID[domain.BusinessUnit](r.BusinessUnitID),
		Slug: r.Slug, Name: r.Name, Description: r.Description,
		State: domain.State(r.State), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func environmentView(r dbq.PcEnvironment) Environment {
	return Environment{
		ID: idOf[domain.Environment](r.ID), Team: optID[domain.Team](r.TeamID),
		Slug: r.Slug, Name: r.Name, Description: r.Description, Kind: domain.EnvironmentKind(r.Kind),
		State: domain.State(r.State), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// Scope paths of hierarchy rows (the permission checks' input).

func businessUnitPath(org ids.OrgID, bu ids.UUID) domain.Path {
	return domain.OrgPath(org).Child(domain.ScopeBusinessUnit, bu)
}

func teamPath(org ids.OrgID, t dbq.PcTeam) domain.Path {
	p := domain.OrgPath(org)
	if t.BusinessUnitID != nil {
		p = p.Child(domain.ScopeBusinessUnit, *t.BusinessUnitID)
	}
	return p.Child(domain.ScopeTeam, t.ID)
}
