// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
	"time"
)

var (
	nbf = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	exp = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
)

func claims() Claims {
	return Claims{
		Version: 1, LicenceID: "lic-1", Licensee: "Acme Ltd", CustomerID: "cus_1", Edition: Team,
		MaxAgents: 50, MaxOrgs: 3, IssuedAt: nbf, NotBefore: nbf, ExpiresAt: exp,
	}
}

func TestT034_ExpiryGraceThenCommunity(t *testing.T) {
	c := claims()
	cases := []struct {
		name    string
		now     time.Time
		status  Status
		edition Edition
		agents  int
		warn    bool
	}{
		{"before nbf", nbf.Add(-time.Hour), StatusNotYetValid, Community, 5, true},
		{"valid", nbf.Add(24 * time.Hour), StatusValid, Team, 50, false},
		{"expiring soon", exp.Add(-10 * 24 * time.Hour), StatusValid, Team, 50, true},
		{"just expired", exp.Add(time.Second), StatusGrace, Team, 50, true},
		{"last grace day", exp.Add(GracePeriod - time.Second), StatusGrace, Team, 50, true},
		{"grace over", exp.Add(GracePeriod), StatusExpired, Community, 5, true},
		{"long expired", exp.Add(365 * 24 * time.Hour), StatusExpired, Community, 5, true},
	}
	for _, tc := range cases {
		e := Evaluate(c, tc.now)
		if e.Status != tc.status || e.Edition != tc.edition || e.Limits.MaxAgents != tc.agents || (e.Warning != "") != tc.warn {
			t.Errorf("%s: got status=%s edition=%s agents=%d warning=%q", tc.name, e.Status, e.Edition, e.Limits.MaxAgents, e.Warning)
		}
	}
	if e := Evaluate(c, exp.Add(time.Hour)); !e.GraceEndsAt.Equal(exp.Add(GracePeriod)) {
		t.Errorf("grace end = %v", e.GraceEndsAt)
	}
}

func TestInvalidClaimsFallBackToCommunity(t *testing.T) {
	for name, mutate := range map[string]func(*Claims){
		"version":       func(c *Claims) { c.Version = 2 },
		"community":     func(c *Claims) { c.Edition = Community },
		"unknown":       func(c *Claims) { c.Edition = "platinum" },
		"zero orgs":     func(c *Claims) { c.MaxOrgs = 0 },
		"negative":      func(c *Claims) { c.MaxAgents = -5 },
		"exp<=nbf":      func(c *Claims) { c.ExpiresAt = c.NotBefore },
		"missing dates": func(c *Claims) { c.IssuedAt = time.Time{} },
		"no licensee":   func(c *Claims) { c.Licensee = "" },
	} {
		c := claims()
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("%s: Validate = %v", name, err)
		}
		e := Evaluate(c, nbf.Add(time.Hour))
		if e.Status != StatusInvalid || e.Edition != Community || e.Limits != CommunityLimits {
			t.Errorf("%s: evaluated to %+v, want Community/INVALID", name, e)
		}
	}
}

func TestEditionLimits(t *testing.T) {
	com := CommunityEntitlements()
	if err := com.CheckOrgs(0); err != nil {
		t.Fatalf("first org refused: %v", err)
	}
	if err := com.CheckOrgs(1); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("second org allowed on Community: %v", err)
	}
	if err := com.CheckAgents(4); err != nil {
		t.Fatalf("fifth agent refused: %v", err)
	}
	if err := com.CheckAgents(5); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("sixth agent allowed on Community: %v", err)
	}
	c := claims()
	c.MaxAgents, c.MaxOrgs = Unlimited, Unlimited
	ent := Evaluate(c, nbf.Add(time.Hour))
	if ent.CheckAgents(1_000_000) != nil || ent.CheckOrgs(10_000) != nil {
		t.Fatal("unlimited licence enforced a cap")
	}
	if Invalid("x").CheckAgents(5) == nil {
		t.Fatal("invalid licence must fall back to Community limits")
	}
}
