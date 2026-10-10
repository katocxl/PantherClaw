// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
)

// TestHR170_NewGrantRequirementsAreSatisfiable (G0 M5 part 2 decisions 2,
// 4 and 6): a grant's approval names a default approver role, its step-up
// the launcher or the principal by WebAuthn, and a deadline, if any, is 5
// minutes to 7 days.
func TestHR170_NewGrantRequirementsAreSatisfiable(t *testing.T) {
	ok := `[{"operations": ["payments.refund.create"], "approval": {"role": "approver", "count": 3, "deadline_seconds": 3600}, "reason": "R_A"},
		{"operations": ["payments.refund.create"], "step_up": {"subject": "principal", "method": "webauthn"}, "reason": "R_B"}]`
	if _, err := DecodeRequirements([]byte(ok)); err != nil {
		t.Fatalf("valid requirements: %v", err)
	}
	for name, raw := range map[string]string{
		"a custom role":       `[{"operations": ["a.b"], "approval": {"role": "refund_approver", "count": 1}, "reason": "R_X"}]`,
		"six approvers":       `[{"operations": ["a.b"], "approval": {"role": "approver", "count": 6}, "reason": "R_X"}]`,
		"a step-up by a user": `[{"operations": ["a.b"], "step_up": {"subject": "user", "method": "webauthn"}, "reason": "R_X"}]`,
		"a step-up by SMS":    `[{"operations": ["a.b"], "step_up": {"subject": "launcher", "method": "sms"}, "reason": "R_X"}]`,
		"a short deadline":    `[{"operations": ["a.b"], "approval": {"role": "approver", "count": 1, "deadline_seconds": 60}, "reason": "R_X"}]`,
	} {
		if _, err := DecodeRequirements([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
