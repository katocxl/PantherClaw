// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package tenancyrpc serves TenancyService and AccessService over Connect.
// Handlers only translate: ids are parsed into typed ids, requests become
// use-case calls, results become protos. Authentication, the coarse
// permission check and protovalidate have run before a handler is called;
// the use cases authorize at the resource's scope.
package tenancyrpc

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// errInvalidID reports an id that is not a canonical UUIDv7: no such entity
// can exist.
var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// parseID parses a required id.
func parseID[K ids.Kind](s string) (ids.ID[K], error) {
	id, err := ids.Parse[K](s)
	if err != nil {
		return ids.ID[K]{}, errInvalidID
	}
	return id, nil
}

// parseOptID parses an optional id ("" is the zero id).
func parseOptID[K ids.Kind](s string) (ids.ID[K], error) {
	if s == "" {
		return ids.ID[K]{}, nil
	}
	return parseID[K](s)
}

func pageOf(size int32, token string) (page.Request, error) { return page.Parse(size, token) }

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func idString[K ids.Kind](id ids.ID[K]) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

var entityState = map[td.State]pantherclawv1.EntityState{
	td.Active:   pantherclawv1.EntityState_ENTITY_STATE_ACTIVE,
	td.Archived: pantherclawv1.EntityState_ENTITY_STATE_ARCHIVED,
}

var envKindToProto = map[td.EnvironmentKind]pantherclawv1.EnvironmentKind{
	td.Development: pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_DEVELOPMENT,
	td.Staging:     pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_STAGING,
	td.Production:  pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION,
}

var envKindFromProto = map[pantherclawv1.EnvironmentKind]td.EnvironmentKind{
	pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_DEVELOPMENT: td.Development,
	pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_STAGING:     td.Staging,
	pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION:  td.Production,
}

var accountState = map[td.AccountState]pantherclawv1.AccountState{
	td.Enabled:  pantherclawv1.AccountState_ACCOUNT_STATE_ACTIVE,
	td.Disabled: pantherclawv1.AccountState_ACCOUNT_STATE_DISABLED,
}

var accountStateFromProto = map[pantherclawv1.AccountState]td.AccountState{
	pantherclawv1.AccountState_ACCOUNT_STATE_ACTIVE:   td.Enabled,
	pantherclawv1.AccountState_ACCOUNT_STATE_DISABLED: td.Disabled,
}

var scopeTypeToProto = map[td.ScopeType]pantherclawv1.ScopeType{
	td.ScopeOrg:          pantherclawv1.ScopeType_SCOPE_TYPE_ORG,
	td.ScopeBusinessUnit: pantherclawv1.ScopeType_SCOPE_TYPE_BUSINESS_UNIT,
	td.ScopeTeam:         pantherclawv1.ScopeType_SCOPE_TYPE_TEAM,
	td.ScopeEnvironment:  pantherclawv1.ScopeType_SCOPE_TYPE_ENVIRONMENT,
}

var scopeTypeFromProto = map[pantherclawv1.ScopeType]td.ScopeType{
	pantherclawv1.ScopeType_SCOPE_TYPE_ORG:           td.ScopeOrg,
	pantherclawv1.ScopeType_SCOPE_TYPE_BUSINESS_UNIT: td.ScopeBusinessUnit,
	pantherclawv1.ScopeType_SCOPE_TYPE_TEAM:          td.ScopeTeam,
	pantherclawv1.ScopeType_SCOPE_TYPE_ENVIRONMENT:   td.ScopeEnvironment,
}

var principalTypeToProto = map[td.PrincipalKind]pantherclawv1.PrincipalType{
	td.KindUser:           pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER,
	td.KindServiceAccount: pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT,
}

var principalTypeFromProto = map[pantherclawv1.PrincipalType]td.PrincipalKind{
	pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER:            td.KindUser,
	pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT: td.KindServiceAccount,
}

var invitationState = map[app.InvitationState]pantherclawv1.InvitationState{
	app.InvitationPending:  pantherclawv1.InvitationState_INVITATION_STATE_PENDING,
	app.InvitationAccepted: pantherclawv1.InvitationState_INVITATION_STATE_ACCEPTED,
	app.InvitationRevoked:  pantherclawv1.InvitationState_INVITATION_STATE_REVOKED,
	app.InvitationExpired:  pantherclawv1.InvitationState_INVITATION_STATE_EXPIRED,
}

func orgProto(o app.Org) *pantherclawv1.Org {
	return &pantherclawv1.Org{Id: o.ID.String(), Name: o.Name, CreateTime: ts(o.CreatedAt)}
}

func businessUnitProto(b app.BusinessUnit) *pantherclawv1.BusinessUnit {
	return &pantherclawv1.BusinessUnit{
		Id: b.ID.String(), Slug: b.Slug, Name: b.Name, Description: b.Description, State: entityState[b.State],
		CreateTime: ts(b.CreatedAt), UpdateTime: ts(b.UpdatedAt),
	}
}

func teamProto(t app.Team) *pantherclawv1.Team {
	return &pantherclawv1.Team{
		Id: t.ID.String(), BusinessUnitId: idString(t.BusinessUnit), Slug: t.Slug, Name: t.Name,
		Description: t.Description, State: entityState[t.State], CreateTime: ts(t.CreatedAt), UpdateTime: ts(t.UpdatedAt),
	}
}

func environmentProto(e app.Environment) *pantherclawv1.Environment {
	return &pantherclawv1.Environment{
		Id: e.ID.String(), TeamId: idString(e.Team), Slug: e.Slug, Name: e.Name, Description: e.Description,
		Kind: envKindToProto[e.Kind], State: entityState[e.State], CreateTime: ts(e.CreatedAt), UpdateTime: ts(e.UpdatedAt),
	}
}

func memberProto(m app.TeamMember) *pantherclawv1.TeamMember {
	return &pantherclawv1.TeamMember{UserId: m.User.String(), Email: m.Email, DisplayName: m.DisplayName, CreateTime: ts(m.AddedAt)}
}

func userProto(u app.User) *pantherclawv1.User {
	return &pantherclawv1.User{
		Id: u.ID.String(), Issuer: u.Issuer, Subject: u.Subject, Email: u.Email, DisplayName: u.DisplayName,
		State: accountState[u.State], CreateTime: ts(u.CreatedAt), UpdateTime: ts(u.UpdatedAt), LastLoginTime: tsp(u.LastLoginAt),
	}
}

func invitationProto(i app.Invitation) *pantherclawv1.Invitation {
	roles := make([]string, len(i.Roles))
	for n, r := range i.Roles {
		roles[n] = string(r)
	}
	return &pantherclawv1.Invitation{
		Id: i.ID.String(), Email: i.Email, Roles: roles, State: invitationState[i.State], Bootstrap: i.Bootstrap,
		CreatedBy: i.CreatedBy, CreateTime: ts(i.CreatedAt), ExpireTime: ts(i.ExpiresAt), AcceptTime: tsp(i.AcceptedAt),
		AcceptedUserId: idString(i.AcceptedUser),
	}
}

func scopeProto(s td.Scope) *pantherclawv1.Scope {
	out := &pantherclawv1.Scope{Type: scopeTypeToProto[s.Type]}
	if s.Type != td.ScopeOrg {
		out.Id = s.ID.String()
	}
	return out
}

func bindingProto(b app.RoleBinding) *pantherclawv1.RoleBinding {
	return &pantherclawv1.RoleBinding{
		Id: b.ID.String(), Role: string(b.Role),
		Principal: &pantherclawv1.Principal{Type: principalTypeToProto[b.Principal.Kind], Id: b.Principal.ID.String()},
		Scope:     scopeProto(b.Scope), CreatedBy: b.CreatedBy, CreateTime: ts(b.CreatedAt),
	}
}

func roleProto(r td.Role) *pantherclawv1.Role {
	out := &pantherclawv1.Role{Name: string(r.Name), Title: r.Title, Description: r.Description, HumanOnly: r.HumanOnly()}
	for _, p := range r.Permissions {
		out.Permissions = append(out.Permissions, string(p))
	}
	for _, s := range r.Scopes {
		out.ScopeTypes = append(out.ScopeTypes, scopeTypeToProto[s])
	}
	return out
}
