// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// RoleName identifies a default role (SB-2, F581). Custom roles are a later,
// Enterprise feature.
type RoleName string

// Default roles.
const (
	RoleOrgAdmin          RoleName = "org_admin"
	RoleSecurityAdmin     RoleName = "security_admin"
	RoleAgentOwner        RoleName = "agent_owner"
	RolePolicyAuthor      RoleName = "policy_author"
	RolePolicyPublisher   RoleName = "policy_publisher"
	RoleApprover          RoleName = "approver"
	RoleResponder         RoleName = "responder"
	RoleAuditor           RoleName = "auditor"
	RoleDeveloper         RoleName = "developer"
	RoleViewer            RoleName = "viewer"
	RoleRunLauncher       RoleName = "run_launcher"
	RoleAgentAdmitter     RoleName = "agent_admitter"
	RoleIdentityPublisher RoleName = "identity_publisher"
)

// Role is a named set of permissions and the scope types it may be bound at.
type Role struct {
	Name        RoleName
	Title       string
	Description string
	Permissions []Permission
	Scopes      []ScopeType
}

// Has reports whether the role contains p.
func (r Role) Has(p Permission) bool { return slices.Contains(r.Permissions, p) }

// HumanOnly reports whether the role contains a human-only permission; such
// a role can never be bound to a service account.
func (r Role) HumanOnly() bool { return slices.ContainsFunc(r.Permissions, Permission.HumanOnly) }

// BindableAt reports whether the role may be bound at scope type t.
func (r Role) BindableAt(t ScopeType) bool { return slices.Contains(r.Scopes, t) }

var (
	anyScope = []ScopeType{ScopeOrg, ScopeBusinessUnit, ScopeTeam, ScopeEnvironment}
	orgScope = []ScopeType{ScopeOrg}
	// basicReads lets a principal see the hierarchy it works in.
	basicReads = []Permission{PermOrgRead, PermBusinessUnitRead, PermTeamRead, PermEnvironmentRead}
)

func with(ps ...[]Permission) []Permission {
	var out []Permission
	for _, p := range ps {
		for _, x := range p {
			if !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	return out
}

// roles are the default roles. Platform administration (Org Admin) never
// implies business approval, policy publication or restricted evidence
// access (F583, T-043): those come only from their own roles.
var roles = []Role{
	{
		Name: RoleOrgAdmin, Title: "Org Admin", Scopes: orgScope,
		Description: "Administers the organization: hierarchy, users, invitations, roles and service accounts. Cannot approve actions, publish policies or read restricted evidence.",
		Permissions: with(basicReads, []Permission{
			PermOrgUpdate, PermBusinessUnitManage, PermTeamManage, PermTeamMembersManage, PermEnvironmentManage,
			PermUserRead, PermUserManage, PermInvitationRead, PermInvitationManage, PermRoleRead, PermRoleBind,
			PermServiceAccountRead, PermServiceAccountManage, PermAuditRead, PermAgentRead, PermRunRead,
			PermWaitlistRead, PermIssuerRead, PermIssuerManage,
			PermNotificationRead, PermNotificationManage,
		}),
	},
	{
		Name: RoleSecurityAdmin, Title: "Security Admin", Scopes: orgScope,
		Description: "Watches and contains: reads users, roles and audit, disables compromised users and service accounts, responds to incidents.",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermUserManage, PermRoleRead, PermInvitationRead, PermServiceAccountRead,
			PermServiceAccountManage, PermAuditRead, PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage,
			PermWaitlistRead, PermIssuerRead,
			PermNotificationRead, PermNotificationManage,
		}),
	},
	{
		Name: RoleAgentOwner, Title: "Agent Owner", Scopes: anyScope,
		Description: "Owns agents in scope and is accountable for them.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermAgentManage, PermRunRead, PermRunStart, PermRunManage, PermWaitlistRead, PermAgentEnroll,
		}),
	},
	{
		Name: RolePolicyAuthor, Title: "Policy Author", Scopes: anyScope,
		Description: "Drafts policies and grants in scope; cannot publish them.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermPolicyAuthor}),
	},
	{
		Name: RolePolicyPublisher, Title: "Policy Publisher", Scopes: anyScope,
		Description: "Publishes reviewed policies in scope (human only).",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermPolicyPublish}),
	},
	{
		Name: RoleApprover, Title: "Approver", Scopes: anyScope,
		Description: "Approves or declines held actions in scope (human only).",
		Permissions: with(basicReads, []Permission{PermApprovalRespond}),
	},
	{
		Name: RoleResponder, Title: "Responder", Scopes: anyScope,
		Description: "Investigates and contains incidents in scope.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage}),
	},
	{
		Name: RoleAuditor, Title: "Auditor", Scopes: orgScope,
		Description: "Reads configuration, audit and restricted evidence (human only); changes nothing.",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermRoleRead, PermInvitationRead, PermServiceAccountRead, PermAuditRead,
			PermAgentRead, PermEvidenceReadRestricted, PermRunRead, PermWaitlistRead, PermIssuerRead,
			PermNotificationRead,
		}),
	},
	{
		Name: RoleDeveloper, Title: "Developer", Scopes: anyScope,
		Description: "Builds agents in scope.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermRunRead, PermRunStart}),
	},
	{
		Name: RoleViewer, Title: "Viewer", Scopes: anyScope,
		Description: "Sees the hierarchy in scope.",
		Permissions: with(basicReads),
	},
	{
		Name: RoleRunLauncher, Title: "Run Launcher", Scopes: anyScope,
		Description: "Starts runs in scope for users who present a fresh token from the identity provider (for example a service acting for a signed-in user). The token proves who is represented and grants nothing.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermRunRead, PermRunStart, PermRunRepresent}),
	},
	{
		Name: RoleAgentAdmitter, Title: "Agent Admitter", Scopes: anyScope,
		Description: "Confirms the key fingerprints of new instances of agents in scope that they own or back up (human only). Holding the role alone admits nothing: the admitter must be the agent's owner or backup owner.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermWaitlistRead, PermAgentAdmit}),
	},
	{
		Name: RoleIdentityPublisher, Title: "Identity Publisher", Scopes: anyScope,
		Description: "Activates proposed or widened trusted-issuer entries in scope after reviewing what they widen (human only). Cannot propose them.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermIssuerRead, PermIssuerActivate}),
	},
}

// Roles returns the default roles in a stable order.
func Roles() []Role {
	out := make([]Role, len(roles))
	for i, r := range roles {
		r.Permissions = slices.Clone(r.Permissions)
		r.Scopes = slices.Clone(r.Scopes)
		out[i] = r
	}
	return out
}

// LookupRole returns the role named n.
func LookupRole(n RoleName) (Role, bool) {
	i := slices.IndexFunc(roles, func(r Role) bool { return r.Name == n })
	if i < 0 {
		return Role{}, false
	}
	return roles[i], true
}
