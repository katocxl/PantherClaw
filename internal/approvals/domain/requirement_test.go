// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
)

func in(kind, role string, count int, independent bool, subject, level string) domain.Input {
	method := ""
	if kind == domain.KindStepUp {
		method = domain.MethodWebAuthn
	}
	return domain.Input{
		Kind: kind, Role: role, Count: count, Independent: independent, Subject: subject, Method: method,
		Source: domain.Source{Level: level, Reason: "R"},
	}
}

// TestHR170_RequirementsMergeByRoleAndKeepTheirSources (design decision 14):
// one role merges into one requirement with the larger count and
// independence if either asks; step-ups stay per subject; the order and
// the sources do not depend on the order found.
func TestHR170_RequirementsMergeByRoleAndKeepTheirSources(t *testing.T) {
	ins := []domain.Input{
		in(domain.KindStepUp, "", 0, false, domain.SubjectPrincipal, "policy p@1 rule b"),
		in(domain.KindApproval, "approver", 1, true, "", "grant g r1"),
		in(domain.KindApproval, "approver", 2, false, "", "policy p@1 rule a"),
		in(domain.KindStepUp, "", 0, false, domain.SubjectLauncher, "guardrail team:t r3"),
		in(domain.KindStepUp, "", 0, false, domain.SubjectPrincipal, "grant g r1"),
	}
	got, deadline, err := domain.Merge(ins)
	if err != nil {
		t.Fatal(err)
	}
	if deadline != 0 {
		t.Fatalf("deadline %s with none set", deadline)
	}
	if len(got) != 3 {
		t.Fatalf("got %d requirements, want 3: %+v", len(got), got)
	}
	a := got[0]
	if a.Kind != domain.KindApproval || a.Count != 2 || !a.Independent || len(a.Sources) != 2 || a.Sources[0].Level != "grant g r1" {
		t.Errorf("approval = %+v, want count 2, independent, both sources sorted", a)
	}
	if got[1].Subject != domain.SubjectLauncher || got[2].Subject != domain.SubjectPrincipal || len(got[2].Sources) != 2 {
		t.Errorf("step-ups = %+v, %+v", got[1], got[2])
	}
	rev := slices.Clone(ins)
	slices.Reverse(rev)
	again, _, _ := domain.Merge(rev)
	if !slices.EqualFunc(got, again, func(x, y domain.Requirement) bool {
		return x.Kind == y.Kind && x.Count == y.Count && x.Subject == y.Subject && slices.Equal(x.Sources, y.Sources)
	}) {
		t.Errorf("merge depends on order:\n%+v\n%+v", got, again)
	}
	if domain.Bound(got)[0] != (domain.BoundRequirement{Kind: domain.KindApproval, Role: "approver", Count: 2, Independent: true}) {
		t.Errorf("bound = %+v", domain.Bound(got)[0])
	}
}

// TestHR170_InvalidRequirementsAreRefused (decisions 2 and 4): an approval
// role that is not a default role holding approval.respond, a count out of
// range, a step-up of another subject or method, or a deadline out of
// bounds is REQUIREMENT_INVALID, never a hold anyone could satisfy.
func TestHR170_InvalidRequirementsAreRefused(t *testing.T) {
	bad := map[string]domain.Input{
		"finance.approver": in(domain.KindApproval, "finance.approver", 1, false, "", "x"),
		"org_admin":        in(domain.KindApproval, "org_admin", 1, false, "", "x"),
		"no approvers":     in(domain.KindApproval, "approver", 0, false, "", "x"),
		"six approvers":    in(domain.KindApproval, "approver", 6, false, "", "x"),
		"owner step-up":    in(domain.KindStepUp, "", 0, false, "owner", "x"),
		"another kind":     in("vote", "approver", 1, false, "", "x"),
	}
	sms := in(domain.KindStepUp, "", 0, false, domain.SubjectLauncher, "x")
	sms.Method = "sms"
	bad["sms step-up"] = sms
	short := in(domain.KindApproval, "approver", 1, false, "", "x")
	short.Deadline = time.Minute
	bad["a one-minute deadline"] = short
	long := short
	long.Deadline = 8 * 24 * time.Hour
	bad["an eight-day deadline"] = long
	for name, i := range bad {
		if _, _, err := domain.Merge([]domain.Input{in(domain.KindApproval, "approver", 1, false, "", "ok"), i}); !errors.Is(err, domain.ErrRequirementInvalid) {
			t.Errorf("%s: %v, want REQUIREMENT_INVALID", name, err)
		}
	}
	if !domain.ApprovalRole("approver") || domain.ApprovalRole("security_admin") {
		t.Error("only a default role with approval.respond may be named")
	}
}

// TestHR039_DeadlinesAndConsumeWindows (decision 6): the shortest deadline a
// requirement sets wins, otherwise the org's default (1 hour unless
// shortened); deadlines are whole seconds; an approval is used within 15
// minutes and never after the deadline.
func TestHR039_DeadlinesAndConsumeWindows(t *testing.T) {
	a := in(domain.KindApproval, "approver", 1, false, "", "a")
	a.Deadline = 2 * time.Hour
	b := in(domain.KindStepUp, "", 0, false, domain.SubjectLauncher, "b")
	b.Deadline = 10 * time.Minute
	_, d, err := domain.Merge([]domain.Input{a, b})
	if err != nil || d != 10*time.Minute {
		t.Fatalf("deadline %s, %v; want the shortest, 10m", d, err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 999_000_000, time.UTC)
	if got := domain.Deadline(now, 0, 0); !got.Equal(time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)) {
		t.Errorf("default deadline %s", got)
	}
	if got := domain.Deadline(now, 0, 30*time.Minute); !got.Equal(time.Date(2026, 10, 10, 12, 30, 0, 0, time.UTC)) {
		t.Errorf("org deadline %s", got)
	}
	if got := domain.Deadline(now, 3*24*time.Hour, 30*time.Minute); !got.Equal(now.Add(72 * time.Hour).Truncate(time.Second)) {
		t.Errorf("a requirement's own deadline %s", got)
	}
	deadline := now.Add(time.Hour)
	if got := domain.ConsumeBy(now, deadline, 0); !got.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("consume-by %s", got)
	}
	if got := domain.ConsumeBy(deadline.Add(-time.Minute), deadline, 0); !got.Equal(deadline) {
		t.Errorf("consume-by past the deadline: %s", got)
	}
}
