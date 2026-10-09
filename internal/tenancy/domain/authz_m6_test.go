// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR183_GatewaysConnectionsAndSealingAreHumanOnly: deciding where target
// credentials go and whether actions are enforced is for people holding
// Gateway Admin (G0 M6, HR-183). Org Admin stays bindable to service
// accounts and only reads, and no API key can be scoped to these.
func TestHR183_GatewaysConnectionsAndSealingAreHumanOnly(t *testing.T) {
	manage := []domain.Permission{domain.PermGatewayManage, domain.PermConnectionManage, domain.PermCredentialSeal}
	for _, p := range manage {
		if !p.HumanOnly() || p.APIKeyScopable() || p.Gateway() {
			t.Errorf("%s must be human only and not a gateway permission", p)
		}
	}
	for _, r := range domain.Roles() {
		for _, p := range manage {
			if r.Has(p) != (r.Name == domain.RoleGatewayAdmin) {
				t.Errorf("role %s: %s = %v", r.Name, p, r.Has(p))
			}
		}
	}
	tr := newTree()
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	if admin.CanAnywhere(domain.PermConnectionManage) || !admin.CanAnywhere(domain.PermConnectionRead) {
		t.Error("Org Admin must read connections and never manage them")
	}
	if _, err := domain.CheckBindable(domain.RoleOrgAdmin, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Errorf("Org Admin must stay bindable to service accounts: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleGatewayAdmin, domain.KindServiceAccount, domain.ScopeOrg); !errors.Is(err, domain.ErrHumanOnlyRole) {
		t.Errorf("Gateway Admin bindable to a service account: %v", err)
	}
	sa := serviceAccount(tr.org, bind(domain.RoleGatewayAdmin, domain.ScopeOrg, tr.org.UUID()))
	if sa.CanAnywhere(domain.PermCredentialSeal) {
		t.Error("a service account bound to Gateway Admin can seal credentials")
	}
}

// TestHR113_KillSwitchIsForPeopleHoldingEmergencyResponder: engaging and
// restoring the kill switch is human only and held only by the org-scoped
// Emergency Responder role; everyone who administers or investigates can
// see it.
func TestHR113_KillSwitchIsForPeopleHoldingEmergencyResponder(t *testing.T) {
	if p := domain.PermContainmentKillSwitch; !p.HumanOnly() || p.APIKeyScopable() {
		t.Error("containment.killswitch must be human only")
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermContainmentKillSwitch) != (r.Name == domain.RoleEmergency) {
			t.Errorf("role %s: containment.killswitch = %v", r.Name, r.Has(domain.PermContainmentKillSwitch))
		}
	}
	er, ok := domain.LookupRole(domain.RoleEmergency)
	if !ok || !slices.Equal(er.Scopes, []domain.ScopeType{domain.ScopeOrg}) {
		t.Errorf("Emergency Responder scopes %v, want org only", er.Scopes)
	}
	tr := newTree()
	for _, r := range []domain.RoleName{domain.RoleOrgAdmin, domain.RoleSecurityAdmin, domain.RoleAuditor, domain.RoleResponder} {
		if !user(tr.org, bind(r, domain.ScopeOrg, tr.org.UUID())).CanAnywhere(domain.PermContainmentRead) {
			t.Errorf("%s cannot see the kill switch", r)
		}
	}
}

// TestHR181_GatewayPermissionsAreAnExplicitSet: only the five permissions
// gateways hold are gateway permissions; gateway.read and gateway.manage
// are ordinary permissions for people.
func TestHR181_GatewayPermissionsAreAnExplicitSet(t *testing.T) {
	for _, p := range []domain.Permission{
		domain.PermGatewayAuthorize, domain.PermGatewayDispatch, domain.PermGatewayObserve,
		domain.PermGatewayEnroll, domain.PermGatewaySync,
	} {
		if !p.Gateway() || p.Known() || !p.Declarable() {
			t.Errorf("%s: gateway=%v known=%v declarable=%v", p, p.Gateway(), p.Known(), p.Declarable())
		}
	}
	for _, p := range []domain.Permission{domain.PermGatewayRead, domain.PermGatewayManage} {
		if p.Gateway() || !p.Known() {
			t.Errorf("%s: gateway=%v known=%v", p, p.Gateway(), p.Known())
		}
	}
}
