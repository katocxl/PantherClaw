// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestExpandRefs(t *testing.T) {
	got := expandRefs("HR-050..052; HR-062, HR-130..131 and T-003")
	want := []string{"HR-050", "HR-051", "HR-052", "HR-062", "HR-130", "HR-131"}
	if !slices.Equal(got, want) {
		t.Fatalf("expandRefs = %v, want %v", got, want)
	}
}

func TestMissing(t *testing.T) {
	rules := []Item{{ID: "HR-001", Due: "M1.5"}, {ID: "HR-004", Due: "M1"}, {ID: "HR-090", Due: "M3"}, {ID: "HR-130", Due: "M0"}}
	threats := []Item{
		{ID: "T-003", Due: "M1", Mitigate: []string{"HR-050"}},
		{ID: "T-040", Due: "M0", Mitigate: []string{"HR-130"}},
		{ID: "T-016", Due: "M1", Mitigate: []string{"HR-062"}},
	}
	tests := map[string]bool{"TestHR004": true, "TestHR130": true, "TestT003": true}
	got := Missing(rules, threats, tests, "M1")
	if len(got) != 1 || !strings.HasPrefix(got[0], "T-016") {
		t.Fatalf("Missing = %v, want only T-016 (HR-001 is due at M1.5, HR-090 at M3)", got)
	}
	if got := Missing(rules, threats, tests, "M1.5"); len(got) != 2 {
		t.Fatalf("through M1.5: %v", got)
	}
}

func TestDeliveryOrder(t *testing.T) {
	// ADR-0017: the range (M12) lands before the preview, so its rules are due
	// before those of M10; M14 lands before M13.
	rules := []Item{{ID: "HR-120", Due: "M12"}, {ID: "HR-200", Due: "M10"}}
	if got := Missing(rules, nil, map[string]bool{}, "M9"); len(got) != 0 {
		t.Fatalf("through M9: %v, want nothing due", got)
	}
	if got := Missing(rules, nil, map[string]bool{}, "M12"); len(got) != 1 || !strings.HasPrefix(got[0], "HR-120") {
		t.Fatalf("through M12: %v, want only HR-120", got)
	}
	if milestoneIndex("M14") >= milestoneIndex("M13") {
		t.Fatalf("M14 must come before M13")
	}
}

func TestRunAgainstRepository(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-root", "../..", "-through", "M1"}, &out, &errb)
	if code != 0 {
		t.Fatalf("repository traceability through M1 failed (%d):\n%s%s", code, out.String(), errb.String())
	}
	if code := run([]string{"-root", "../..", "-through", "M99"}, &out, &errb); code != 2 {
		t.Fatalf("unknown milestone accepted")
	}
}
