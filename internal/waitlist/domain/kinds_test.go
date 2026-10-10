// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

func seconds(n int32) *int32 { return &n }

// TestHR177_DeadlinesComeFromTheKindAndOnlyShorten: each kind has its
// decision-6 deadline, an org setting may only shorten it, and only access
// requests and tool reviews end at their deadline (a RECONCILIATION entry
// never resolves by itself).
func TestHR177_DeadlinesComeFromTheKindAndOnlyShorten(t *testing.T) {
	day := 24 * time.Hour
	for kind, want := range map[string]time.Duration{
		domain.KindAccessRequest: 7 * day, domain.KindToolReview: 30 * day, domain.KindRestoration: day,
		domain.KindReconciliation: 3 * day, domain.KindAdmission: 7 * day,
	} {
		if got := domain.Deadline(kind, nil); got != want {
			t.Errorf("%s: %s, want %s", kind, got, want)
		}
	}
	if got := domain.Deadline(domain.KindAccessRequest, seconds(3600)); got != time.Hour {
		t.Errorf("a shorter setting: %s", got)
	}
	if got := domain.Deadline(domain.KindRestoration, seconds(10*86400)); got != day {
		t.Errorf("a setting never lengthens: %s", got)
	}
	for kind, want := range map[string]bool{
		domain.KindAccessRequest: true, domain.KindToolReview: true, domain.KindReconciliation: false,
		domain.KindRestoration: false, domain.KindActionHold: false, domain.KindAdmission: false,
	} {
		if domain.Expires(kind) != want {
			t.Errorf("Expires(%s) = %v", kind, !want)
		}
	}
}

// TestHR177_DecidersComeFromPermissions: holds and restorations follow the
// approval rules; every other kind names the permission that decides it.
func TestHR177_DecidersComeFromPermissions(t *testing.T) {
	for kind, want := range map[string]td.Permission{
		domain.KindAdmission: td.PermAgentAdmit, domain.KindAccessRequest: td.PermGrantIssue,
		domain.KindToolReview: td.PermPackageActivate, domain.KindReconciliation: td.PermIncidentRespond,
	} {
		if p, ok := domain.DeciderPermission(kind); !ok || p != want {
			t.Errorf("%s: %s %v", kind, p, ok)
		}
	}
	for _, kind := range []string{domain.KindActionHold, domain.KindRestoration} {
		if _, ok := domain.DeciderPermission(kind); ok {
			t.Errorf("%s is decided under the approval rules", kind)
		}
	}
}
