// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// Permission names one capability. Every RPC declares the permission it
// requires ("// permission: <name>" in its proto, BUILD_GUIDE §3.2); a test
// checks each declared name against this catalog.
type Permission string

// Pseudo-permissions used only in RPC declarations, never in roles.
const (
	// PermPublic marks procedures callable without authentication.
	PermPublic Permission = "public"
	// PermAuthenticated marks procedures any authenticated user or service
	// account may call (for example "who am I").
	PermAuthenticated Permission = "authenticated"
)

// Tenancy and access permissions (M2).
const (
	PermOrgRead              Permission = "org.read"
	PermOrgUpdate            Permission = "org.update"
	PermBusinessUnitRead     Permission = "business_unit.read"
	PermBusinessUnitManage   Permission = "business_unit.manage"
	PermTeamRead             Permission = "team.read"
	PermTeamManage           Permission = "team.manage"
	PermTeamMembersManage    Permission = "team.members.manage"
	PermEnvironmentRead      Permission = "environment.read"
	PermEnvironmentManage    Permission = "environment.manage"
	PermUserRead             Permission = "user.read"
	PermUserManage           Permission = "user.manage"
	PermInvitationRead       Permission = "invitation.read"
	PermInvitationManage     Permission = "invitation.manage"
	PermRoleRead             Permission = "role.read"
	PermRoleBind             Permission = "role.bind"
	PermServiceAccountRead   Permission = "service_account.read"
	PermServiceAccountManage Permission = "service_account.manage"
	PermAuditRead            Permission = "audit.read"
)

// Permissions of later milestones. They are defined now so that the default
// roles and the separation-of-duties tests cover them before their RPCs
// exist (F581, F583).
const (
	PermAgentRead              Permission = "agent.read"               // M3
	PermAgentManage            Permission = "agent.manage"             // M3
	PermPolicyAuthor           Permission = "policy.author"            // M4
	PermPolicyPublish          Permission = "policy.publish"           // M4/M11, human only
	PermApprovalRespond        Permission = "approval.respond"         // M5, human only
	PermIncidentRespond        Permission = "incident.respond"         // M10
	PermEvidenceReadRestricted Permission = "evidence.read_restricted" // M7, human only
)

// Gateway permissions are held only by authenticated gateways (M1.5 dev
// gateway, M6 mTLS), never by users, service accounts or roles.
const (
	PermGatewayAuthorize Permission = "gateway.authorize"
	PermGatewayDispatch  Permission = "gateway.dispatch"
)

// catalog lists every grantable permission.
var catalog = []Permission{
	PermOrgRead, PermOrgUpdate,
	PermBusinessUnitRead, PermBusinessUnitManage,
	PermTeamRead, PermTeamManage, PermTeamMembersManage,
	PermEnvironmentRead, PermEnvironmentManage,
	PermUserRead, PermUserManage,
	PermInvitationRead, PermInvitationManage,
	PermRoleRead, PermRoleBind,
	PermServiceAccountRead, PermServiceAccountManage,
	PermAuditRead,
	PermAgentRead, PermAgentManage,
	PermPolicyAuthor, PermPolicyPublish,
	PermApprovalRespond, PermIncidentRespond, PermEvidenceReadRestricted,
}

// humanOnly permissions can never be exercised by a service account or an
// API key, whatever their bindings say (ARCHITECTURE §10: "pck_ keys never
// able to approve"; F583).
var humanOnly = []Permission{PermApprovalRespond, PermPolicyPublish, PermEvidenceReadRestricted}

// Catalog returns every grantable permission in a stable order.
func Catalog() []Permission { return slices.Clone(catalog) }

// Known reports whether p is a grantable permission.
func (p Permission) Known() bool { return slices.Contains(catalog, p) }

// HumanOnly reports whether only a human may hold p.
func (p Permission) HumanOnly() bool { return slices.Contains(humanOnly, p) }

// Gateway reports whether p belongs to gateways.
func (p Permission) Gateway() bool { return strings.HasPrefix(string(p), "gateway.") }

// Declarable reports whether an RPC may declare p as its requirement.
func (p Permission) Declarable() bool {
	return p == PermPublic || p == PermAuthenticated || p == PermGatewayAuthorize || p == PermGatewayDispatch || p.Known()
}

// APIKeyScopable reports whether p may appear in an API key's scopes.
func (p Permission) APIKeyScopable() bool { return p.Known() && !p.HumanOnly() }
