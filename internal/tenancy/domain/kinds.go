// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the tenancy model (BUILD_GUIDE §8 M2, F573, F581):
// the org → business unit → team → environment hierarchy, the permission
// catalog, the default roles, scopes and the pure authorization check, and
// separation-of-duties primitives. It does no I/O.
package domain

import "github.com/katocxl/pantherclaw/internal/platform/ids"

// BusinessUnit is a business unit (Business edition).
type BusinessUnit struct{}

// KindName implements ids.Kind.
func (BusinessUnit) KindName() string { return "business_unit" }

// Team is a team, directly under the org or under a business unit.
type Team struct{}

// KindName implements ids.Kind.
func (Team) KindName() string { return "team" }

// Environment is a development, staging or production environment.
type Environment struct{}

// KindName implements ids.Kind.
func (Environment) KindName() string { return "environment" }

// User is one OIDC identity inside one org.
type User struct{}

// KindName implements ids.Kind.
func (User) KindName() string { return "user" }

// ServiceAccount is a non-human principal.
type ServiceAccount struct{}

// KindName implements ids.Kind.
func (ServiceAccount) KindName() string { return "service_account" }

// RoleBinding is one role granted to one principal at one scope.
type RoleBinding struct{}

// KindName implements ids.Kind.
func (RoleBinding) KindName() string { return "role_binding" }

// Invitation is a single-use invitation to join an org.
type Invitation struct{}

// KindName implements ids.Kind.
func (Invitation) KindName() string { return "invitation" }

// Typed identifiers.
type (
	BusinessUnitID   = ids.ID[BusinessUnit]
	TeamID           = ids.ID[Team]
	EnvironmentID    = ids.ID[Environment]
	UserID           = ids.ID[User]
	ServiceAccountID = ids.ID[ServiceAccount]
	RoleBindingID    = ids.ID[RoleBinding]
	InvitationID     = ids.ID[Invitation]
)
