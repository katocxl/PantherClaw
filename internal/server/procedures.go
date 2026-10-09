// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// procedurePermissions maps every procedure to the permission its proto
// declares ("// permission: …", BUILD_GUIDE §3.2). The authentication
// interceptor refuses procedures missing from it, and
// TestProcedurePermissionsMatchProtos keeps it equal to the protos.
var procedurePermissions = map[string]td.Permission{
	pantherclawv1connect.AccessServiceCreateInvitationProcedure:                "invitation.manage",
	pantherclawv1connect.AccessServiceCreateRoleBindingProcedure:               "role.bind",
	pantherclawv1connect.AccessServiceDeleteRoleBindingProcedure:               "role.bind",
	pantherclawv1connect.AccessServiceGetUserProcedure:                         "user.read",
	pantherclawv1connect.AccessServiceListInvitationsProcedure:                 "invitation.read",
	pantherclawv1connect.AccessServiceListRoleBindingsProcedure:                "role.read",
	pantherclawv1connect.AccessServiceListRolesProcedure:                       "authenticated",
	pantherclawv1connect.AccessServiceListUsersProcedure:                       "user.read",
	pantherclawv1connect.AccessServiceRevokeInvitationProcedure:                "invitation.manage",
	pantherclawv1connect.AccessServiceSetUserStateProcedure:                    "user.manage",
	pantherclawv1connect.AccessServiceWhoAmIProcedure:                          "authenticated",
	pantherclawv1connect.AgentServiceClaimAgentProcedure:                       "agent.manage",
	pantherclawv1connect.AgentServiceCreateAgentProcedure:                      "agent.manage",
	pantherclawv1connect.AgentServiceGetAgentProcedure:                         "agent.read",
	pantherclawv1connect.AgentServiceListAgentChangesProcedure:                 "agent.read",
	pantherclawv1connect.AgentServiceListAgentsProcedure:                       "agent.read",
	pantherclawv1connect.AgentServiceRetireAgentProcedure:                      "agent.manage",
	pantherclawv1connect.AgentServiceSuspendAgentProcedure:                     "agent.manage",
	pantherclawv1connect.AgentServiceTransferOwnershipProcedure:                "agent.manage",
	pantherclawv1connect.AgentServiceUpdateAgentProcedure:                      "agent.manage",
	pantherclawv1connect.AuthorityServiceAuthorizeProcedure:                    "gateway.authorize",
	pantherclawv1connect.AuthorityServiceBeginDispatchProcedure:                "gateway.dispatch",
	pantherclawv1connect.AuthorityServiceRecordExecutionProcedure:              "gateway.dispatch",
	pantherclawv1connect.RunServiceEndRunProcedure:                             "run.manage",
	pantherclawv1connect.RunServiceGetRunProcedure:                             "run.read",
	pantherclawv1connect.RunServiceListRunsProcedure:                           "run.read",
	pantherclawv1connect.RunServiceStartRunProcedure:                           "run.start",
	pantherclawv1connect.ServiceAccountServiceAddServiceAccountKeyProcedure:    "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceCreateApiKeyProcedure:            "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceCreateServiceAccountProcedure:    "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceGetServiceAccountProcedure:       "service_account.read",
	pantherclawv1connect.ServiceAccountServiceListApiKeysProcedure:             "service_account.read",
	pantherclawv1connect.ServiceAccountServiceListServiceAccountKeysProcedure:  "service_account.read",
	pantherclawv1connect.ServiceAccountServiceListServiceAccountsProcedure:     "service_account.read",
	pantherclawv1connect.ServiceAccountServiceRevokeApiKeyProcedure:            "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceRevokeServiceAccountKeyProcedure: "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceSetServiceAccountStateProcedure:  "service_account.manage",
	pantherclawv1connect.ServiceAccountServiceUpdateServiceAccountProcedure:    "service_account.manage",
	pantherclawv1connect.SystemServiceGetBuildInfoProcedure:                    "public",
	pantherclawv1connect.TenancyServiceAddTeamMemberProcedure:                  "team.members.manage",
	pantherclawv1connect.TenancyServiceArchiveBusinessUnitProcedure:            "business_unit.manage",
	pantherclawv1connect.TenancyServiceArchiveEnvironmentProcedure:             "environment.manage",
	pantherclawv1connect.TenancyServiceArchiveTeamProcedure:                    "team.manage",
	pantherclawv1connect.TenancyServiceCreateBusinessUnitProcedure:             "business_unit.manage",
	pantherclawv1connect.TenancyServiceCreateEnvironmentProcedure:              "environment.manage",
	pantherclawv1connect.TenancyServiceCreateTeamProcedure:                     "team.manage",
	pantherclawv1connect.TenancyServiceGetBusinessUnitProcedure:                "business_unit.read",
	pantherclawv1connect.TenancyServiceGetEnvironmentProcedure:                 "environment.read",
	pantherclawv1connect.TenancyServiceGetOrgProcedure:                         "org.read",
	pantherclawv1connect.TenancyServiceGetTeamProcedure:                        "team.read",
	pantherclawv1connect.TenancyServiceListBusinessUnitsProcedure:              "business_unit.read",
	pantherclawv1connect.TenancyServiceListEnvironmentsProcedure:               "environment.read",
	pantherclawv1connect.TenancyServiceListTeamMembersProcedure:                "team.read",
	pantherclawv1connect.TenancyServiceListTeamsProcedure:                      "team.read",
	pantherclawv1connect.TenancyServiceRemoveTeamMemberProcedure:               "team.members.manage",
	pantherclawv1connect.TenancyServiceUpdateBusinessUnitProcedure:             "business_unit.manage",
	pantherclawv1connect.TenancyServiceUpdateEnvironmentProcedure:              "environment.manage",
	pantherclawv1connect.TenancyServiceUpdateOrgProcedure:                      "org.update",
	pantherclawv1connect.TenancyServiceUpdateTeamProcedure:                     "team.manage",
	pantherclawv1connect.WaitlistServiceGetWaitlistEntryProcedure:              "waitlist.read",
	pantherclawv1connect.WaitlistServiceListWaitlistEntriesProcedure:           "waitlist.read",
}
