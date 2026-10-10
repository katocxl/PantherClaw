// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m5p2Procedures are the M5 part 2 procedures (G0 M5 part 2): approval
// requests, the waitlist's write paths, waiting and evidence from
// workloads, and restorations. A procedure declared "authenticated" checks
// the caller's relation to the run or request in its use case (the run's
// launcher or principal, an eligible decider). They live beside
// procedurePermissions to keep the shared map small;
// TestProcedurePermissionsMatchProtos checks the merged map.
var m5p2Procedures = map[string]td.Permission{
	pantherclawv1connect.ApprovalServiceListApprovalRequestsProcedure:    "authenticated",
	pantherclawv1connect.ApprovalServiceGetApprovalRequestProcedure:      "authenticated",
	pantherclawv1connect.ApprovalServiceDeclineApprovalRequestProcedure:  "approval.respond",
	pantherclawv1connect.ApprovalServiceRequestApprovalEvidenceProcedure: "approval.respond",
	pantherclawv1connect.ApprovalServiceProposeNarrowerActionProcedure:   "approval.respond",
	pantherclawv1connect.ApprovalServiceSubmitApprovalEvidenceProcedure:  "authenticated",
	pantherclawv1connect.ApprovalServiceDeclineApprovalBatchProcedure:    "approval.respond",
	pantherclawv1connect.WaitlistServiceAssignWaitlistEntryProcedure:     "waitlist.read",
	pantherclawv1connect.WaitlistServiceRequestAccessProcedure:           "authenticated",
	pantherclawv1connect.WaitlistServiceDismissAccessRequestProcedure:    "grant.issue",
	pantherclawv1connect.WaitlistServiceGetEscalationChainProcedure:      "waitlist.read",
	pantherclawv1connect.WaitlistServiceSetEscalationChainProcedure:      "waitlist.manage",
	pantherclawv1connect.WaitlistServiceGetWaitlistSettingsProcedure:     "waitlist.manage",
	pantherclawv1connect.WaitlistServiceUpdateWaitlistSettingsProcedure:  "waitlist.manage",
	pantherclawv1connect.WaitlistServiceGetWaitlistMetricsProcedure:      "waitlist.read",
	pantherclawv1connect.WorkloadServiceWaitProcedure:                    "workload.run",
	pantherclawv1connect.WorkloadServiceSubmitEvidenceProcedure:          "workload.run",
	pantherclawv1connect.WorkloadServiceRequestAccessProcedure:           "workload.run",
	pantherclawv1connect.AgentServiceRequestAgentRestorationProcedure:    "agent.manage",
}

func init() { maps.Copy(procedurePermissions, m5p2Procedures) }
