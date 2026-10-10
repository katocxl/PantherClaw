// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"
	"testing"
)

// TestHR170_NewPoliciesNameOnlyApprovalRoles (G0 M5 part 2 decisions 2 and
// 6): a submitted bundle's approval must name a default role holding
// approval.respond, and a deadline a requirement sets is 5 minutes to 7
// days. A stored bundle is not refused when it compiles; its holds are
// REQUIREMENT_INVALID instead (pipeline tests).
func TestHR170_NewPoliciesNameOnlyApprovalRoles(t *testing.T) {
	bundle := func(approval string) []byte {
		return []byte(`{"id": "org-policy", "version": 1, "rules": [{"id": "hold", "kind": "REQUIRE_APPROVAL", "summary": "over 50",
			"operations": ["payments.refund.create"], "when": "true", "reason": "OVER_50", "approval": ` + approval + `}]}`)
	}
	if _, err := DecodeBundle(bundle(`{"role": "approver", "count": 2, "deadline_seconds": 86400}`)); err != nil {
		t.Fatalf("a valid bundle: %v", err)
	}
	for name, a := range map[string]string{
		"a role that is not an approver role": `{"role": "finance.approver", "count": 1}`,
		"an admin role":                       `{"role": "org_admin", "count": 1}`,
		"a one-minute deadline":               `{"role": "approver", "count": 1, "deadline_seconds": 60}`,
		"an eight-day deadline":               `{"role": "approver", "count": 1, "deadline_seconds": 691200}`,
	} {
		if _, err := DecodeBundle(bundle(a)); err == nil || !strings.Contains(err.Error(), "hold") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
	stored := bundle(`{"role": "finance.approver", "count": 1}`)
	if _, err := decodeStored(stored); err != nil {
		t.Fatalf("a stored bundle naming another role must still compile: %v", err)
	}
}
