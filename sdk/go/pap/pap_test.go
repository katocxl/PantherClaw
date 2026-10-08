// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"regexp"
	"testing"
)

func TestErrorCodesAreUniqueSnakeCase(t *testing.T) {
	t.Parallel()

	snake := regexp.MustCompile(`^[a-z]+(_[a-z]+)*$`)
	seen := map[ErrorCode]bool{}
	for _, c := range ErrorCodes() {
		if seen[c] {
			t.Fatalf("duplicate error code %q", c)
		}
		seen[c] = true
		if !snake.MatchString(string(c)) {
			t.Fatalf("error code %q is not snake_case", c)
		}
	}
	if len(seen) != 16 {
		t.Fatalf("PAP/1 §12 defines 16 error codes, got %d", len(seen))
	}
}

func TestDecisionSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		d              Decision
		permits, holds bool
	}{
		{Allow, true, false},
		{AllowWithObligations, true, false},
		{RequireApproval, false, true},
		{RequireStepUp, false, true},
		{Deny, false, false},
		{CannotAuthorize, false, false},
	}
	for _, tt := range tests {
		if !tt.d.Valid() {
			t.Fatalf("%s should be valid", tt.d)
		}
		if tt.d.Permits() != tt.permits || tt.d.Holds() != tt.holds {
			t.Fatalf("%s: permits=%v holds=%v, want %v %v", tt.d, tt.d.Permits(), tt.d.Holds(), tt.permits, tt.holds)
		}
	}
}

// An unknown decision string must never permit dispatch (fail closed).
func TestUnknownDecisionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", "allow", "ALLOW ", "PERMIT", "OBSERVE"} {
		d := Decision(s)
		if d.Valid() || d.Permits() || d.Holds() {
			t.Fatalf("decision %q must be invalid and non-permitting", s)
		}
	}
}
