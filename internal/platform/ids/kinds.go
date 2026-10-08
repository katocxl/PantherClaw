// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ids

// Org is the tenant root entity.
type Org struct{}

// KindName implements Kind.
func (Org) KindName() string { return "org" }

// OrgID identifies an organization (tenant). Every tenant-scoped repository
// method takes an OrgID explicitly (HR-050, ARCHITECTURE §7).
type OrgID = ID[Org]

// PlatformOrg is the reserved organization that owns platform-level evidence
// (licence changes, platform key events). It is a fixed UUIDv7-shaped value,
// distinct from the zero ID so that a forgotten OrgID never lands in it.
var PlatformOrg = MustParse[Org]("00000000-0000-7000-8000-000000000001")
