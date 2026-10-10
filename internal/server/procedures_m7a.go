// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m7aProcedures are the procedures of M7 track A (G0 M7): the
// gateway-facing verification leases and reports. TestProcedurePermissionsMatchProtos
// checks the merged map.
var m7aProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceClaimVerificationsProcedure: "gateway.verify",
	pantherclawv1connect.GatewayServiceReportObservationProcedure:  "gateway.verify",
}

func init() { maps.Copy(procedurePermissions, m7aProcedures) }
