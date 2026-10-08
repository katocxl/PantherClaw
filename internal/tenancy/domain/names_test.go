// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func TestSlugs(t *testing.T) {
	for s, ok := range map[string]bool{
		"a": true, "prod": true, "team-1": true, "a1-b2": true, strings.Repeat("a", 63): true,
		"": false, "-a": false, "a-": false, "A": false, "a_b": false, "a.b": false, "é": false,
		strings.Repeat("a", 64): false, "a b": false,
	} {
		if domain.ValidSlug(s) != ok {
			t.Errorf("ValidSlug(%q) = %v, want %v", s, !ok, ok)
		}
		if (domain.CheckSlug("slug", s) == nil) != ok {
			t.Errorf("CheckSlug(%q) disagrees with ValidSlug", s)
		}
	}
}

func TestNamesRejectControlAndFormatCharacters(t *testing.T) {
	for _, bad := range []string{"", "   ", "a\x00b", "line\nbreak", "evil\u202egnp.exe", "zero\u200dwidth", "\xff", strings.Repeat("x", 201)} {
		if _, err := domain.CheckName("name", bad); err == nil {
			t.Errorf("CheckName(%q) accepted", bad)
		}
	}
	got, err := domain.CheckName("name", "  Payments Team  ")
	if err != nil || got != "Payments Team" {
		t.Fatalf("CheckName trims: %q, %v", got, err)
	}
	if _, err := domain.CheckName("name", strings.Repeat("é", 200)); err != nil {
		t.Errorf("200 runes rejected: %v", err)
	}
	if d, err := domain.CheckDescription("first\nsecond"); err != nil || d != "first\nsecond" {
		t.Errorf("description with newline: %q, %v", d, err)
	}
	if _, err := domain.CheckDescription("tab\there"); err == nil {
		t.Error("description with a tab accepted")
	}
}

func TestSanitizeClaim(t *testing.T) {
	if got := domain.SanitizeClaim(" Al\u202eice\x07 ", 200); got != "Alice" {
		t.Errorf("SanitizeClaim = %q", got)
	}
	if got := domain.SanitizeClaim(strings.Repeat("é", 10), 3); got != "ééé" {
		t.Errorf("SanitizeClaim cut = %q", got)
	}
}

func TestEmails(t *testing.T) {
	if e, err := domain.CheckEmail("  Alice@Example.COM "); err != nil || e != "alice@example.com" {
		t.Fatalf("CheckEmail = %q, %v", e, err)
	}
	for _, bad := range []string{"", "alice", "@example.com", "alice@", "a b@example.com", "<a@b.c>", "a@b\u202e.c"} {
		if _, err := domain.CheckEmail(bad); err == nil {
			t.Errorf("CheckEmail(%q) accepted", bad)
		}
	}
}
