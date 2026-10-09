// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

var (
	testOrg   = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	agentA    = ids.NewV7()
	envProd   = ids.NewV7()
	alice     = Principal{Kind: PrincipalUser, ID: ids.NewV7()}
	issueTime = mondayNoon
)

func lookupRefund(op string) *defs.Definition {
	if op == "payments.refund.create" {
		return refundDefinition()
	}
	return nil
}

func rootGrant(t *testing.T, bounds string) Grant {
	t.Helper()
	return Grant{
		ID: NewGrantID(), Org: testOrg, Revision: 1, State: StateActive,
		AgentID: agentA, Principal: alice, EnvironmentID: envProd, TaskRef: "refund duplicate charges",
		NotBefore: issueTime, ExpiresAt: issueTime.Add(48 * time.Hour),
		Bounds:     mustBounds(t, bounds),
		Delegation: Delegation{Depth: 2, MaxChildren: 3},
		Grantor:    alice, Basis: "grant.issue at team",
	}
}

func childOf(t *testing.T, p Grant, bounds string) Grant {
	t.Helper()
	c := p
	c.ID, c.Revision, c.Parent, c.Depth = NewGrantID(), 1, p.ID, p.Depth+1
	c.Bounds = mustBounds(t, bounds).Inherit(p.Bounds)
	c.ExpiresAt = issueTime.Add(12 * time.Hour)
	c.Delegation = Delegation{Depth: max(p.Delegation.Depth-1, 0), MaxChildren: 1}
	if c.Delegation.Depth == 0 {
		c.Delegation.MaxChildren = 0
	}
	c.Grantor = Principal{Kind: PrincipalInstance, ID: ids.NewV7()}
	c.Basis = "delegation from grant " + p.ID.String()
	return c
}

func orgEnvelope(t *testing.T, bounds string) Envelope {
	t.Helper()
	return Envelope{ID: NewEnvelopeID(), Org: testOrg, Revision: 1, Scope: Scope{Kind: ScopeOrg}, Name: "org", Bounds: mustBounds(t, bounds)}
}

func issue(g Grant, parent *Grant, envs ...Envelope) error {
	return g.ValidateIssue(IssueContext{Now: issueTime, Envelopes: envs, Lookup: lookupRefund, Parent: parent})
}

func TestHR161_OnlyPeopleIssueRootGrants(t *testing.T) {
	g := rootGrant(t, refundBounds)
	if err := issue(g, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []PrincipalKind{PrincipalInstance, PrincipalServiceAccount} {
		g.Grantor = Principal{Kind: kind, ID: ids.NewV7()}
		if err := issue(g, nil); !errors.Is(err, ErrOutside) {
			t.Fatalf("a %s issued a root grant: %v", kind, err)
		}
	}
}

func TestHR045_GrantMustFitEveryGuardrail(t *testing.T) {
	g := rootGrant(t, refundBounds)
	tight := orgEnvelope(t, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "50"}}}}}`)
	if err := issue(g, nil, tight); !errors.Is(err, ErrOutside) || !strings.Contains(err.Error(), "guardrail") {
		t.Fatalf("a grant over the org guardrail was issued: %v", err)
	}
	loose := orgEnvelope(t, `{"operations": ["payments.*"]}`)
	if err := issue(g, nil, loose); err != nil {
		t.Fatalf("a grant inside the guardrail: %v", err)
	}
	// Dimensions the grant leaves open are not compared: decisions apply
	// the guardrail itself (HR-046).
	open := rootGrant(t, `{"operations": ["payments.refund.create"]}`)
	if err := issue(open, nil, tight); err != nil {
		t.Fatalf("a grant that leaves the amount to the guardrail: %v", err)
	}
	env := tight
	env.MinAttestation = 2
	if err := issue(open, nil, env); !errors.Is(err, ErrOutside) {
		t.Fatalf("a grant below the guardrail's attestation minimum: %v", err)
	}
}

func TestHR047_DelegationCapsAndExpiryCeiling(t *testing.T) {
	root := rootGrant(t, refundBounds)
	child := childOf(t, root, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "20"}}}}}`)
	if err := issue(child, &root); err != nil {
		t.Fatalf("a narrower child: %v", err)
	}
	cases := map[string]func(c, p *Grant, ic *IssueContext){
		"wider than parent": func(c, p *Grant, _ *IssueContext) {
			c.Bounds = mustBounds(t, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "500"}}}}}`).Inherit(p.Bounds)
		},
		"outlives parent": func(c, p *Grant, _ *IssueContext) { c.ExpiresAt = p.ExpiresAt.Add(time.Minute) },
		"over 24 hours": func(c, p *Grant, _ *IssueContext) {
			p.ExpiresAt = issueTime.Add(72 * time.Hour)
			c.ExpiresAt = issueTime.Add(25 * time.Hour)
		},
		"parent cannot delegate": func(_, p *Grant, _ *IssueContext) { p.Delegation = Delegation{} },
		"too deep":               func(c, p *Grant, _ *IssueContext) { p.Depth = DefaultMaxDepth; c.Depth = DefaultMaxDepth + 1 },
		"keeps parent's depth": func(c, p *Grant, _ *IssueContext) {
			c.Delegation = Delegation{Depth: p.Delegation.Depth, MaxChildren: 1}
		},
		"fan-out reached":        func(_, p *Grant, ic *IssueContext) { ic.ActiveChildren = p.Delegation.MaxChildren },
		"lifetime total reached": func(_, _ *Grant, ic *IssueContext) { ic.TotalChildren = MaxChildrenTotal },
		"another principal":      func(c, _ *Grant, _ *IssueContext) { c.Principal = Principal{Kind: PrincipalUser, ID: ids.NewV7()} },
		"another environment":    func(c, _ *Grant, _ *IssueContext) { c.EnvironmentID = ids.NewV7() },
		"lower attestation":      func(c, p *Grant, _ *IssueContext) { p.MinAttestation = 2; c.MinAttestation = 1 },
		"revoked parent":         func(_, p *Grant, _ *IssueContext) { p.State = StateRevoked },
		"expired parent":         func(_, _ *Grant, ic *IssueContext) { ic.Now = issueTime.Add(49 * time.Hour) },
		"starts before parent":   func(c, p *Grant, _ *IssueContext) { c.NotBefore = p.NotBefore.Add(-time.Minute) },
		"more children than root": func(c, p *Grant, _ *IssueContext) {
			c.Delegation = Delegation{Depth: 1, MaxChildren: p.Delegation.MaxChildren + 1}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := root
			c := childOf(t, root, `{}`)
			if err := c.ValidateIssue(IssueContext{Now: issueTime, Lookup: lookupRefund, Parent: &p}); err != nil {
				t.Fatalf("baseline child refused: %v", err)
			}
			ic := IssueContext{Now: issueTime, Lookup: lookupRefund}
			mutate(&c, &p, &ic)
			c.Parent = p.ID
			ic.Parent = &p
			if err := c.ValidateIssue(ic); err == nil {
				t.Fatal("refused delegation was accepted")
			}
		})
	}
}

func TestHR046_EveryLevelIsEvaluatedAtDecisionTime(t *testing.T) {
	root := rootGrant(t, refundBounds)
	child := childOf(t, root, `{}`)
	chain := Chain{Grants: []Grant{root, child}}
	a := refund("80.00", "USD", "duplicate", mondayNoon)
	if fs := append(chain.Coverage(a), chain.Limits(a)...); len(fs) != 0 {
		t.Fatalf("an action within every level was refused: %+v", fs)
	}

	// The root is narrowed after the child was issued: the child is not
	// rewritten, yet the decision applies the root's new bound.
	narrowed := root
	narrowed.Revision = 2
	narrowed.Bounds = mustBounds(t, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "50"}}}}}`).Inherit(root.Bounds)
	chain = Chain{Grants: []Grant{narrowed, child}}
	fs := chain.Limits(a)
	if len(fs) != 1 || fs[0].Level.ID != root.ID.UUID() || fs[0].Level.Revision != 2 || fs[0].Reason() != ReasonGrantLimitExceeded {
		t.Fatalf("narrowed ancestor not applied: %+v", fs)
	}

	// A child row wider than its parent (written around the issuance
	// checks) is still limited by the parent.
	wide := child
	wide.Bounds = mustBounds(t, `{"operations": ["payments.*"]}`)
	chain = Chain{Grants: []Grant{root, wide}}
	a.Operation = "payments.charge.create"
	if fs := chain.Coverage(a); len(fs) == 0 || fs[0].Level.ID != root.ID.UUID() || fs[0].Reason() != ReasonOperationNotGranted {
		t.Fatalf("a wider child escaped its parent: %+v", fs)
	}

	// A guardrail narrowed later applies to existing grants.
	a.Operation = "payments.refund.create"
	env := orgEnvelope(t, `{"params": {"payments.refund.create": {"reason": {"values": {"ids": ["fraudulent"]}}}}}`)
	chain = Chain{Envelopes: []Envelope{env}, Grants: []Grant{root, child}}
	if fs := chain.Limits(a); len(fs) != 1 || fs[0].Reason() != ReasonOutsideGuardrail || !strings.Contains(fs[0].Detail(), "org guardrail") {
		t.Fatalf("narrowed guardrail not applied: %+v", fs)
	}
}

func TestHR046_ValidityOfEveryAncestor(t *testing.T) {
	root := rootGrant(t, refundBounds)
	child := childOf(t, root, `{}`)
	if code, f := (Chain{}).Validity(mondayNoon); code != ReasonNoGrant || f == nil {
		t.Fatalf("no grant: %s", code)
	}
	revoked := root
	revoked.State = StateRevoked
	if code, f := (Chain{Grants: []Grant{revoked, child}}).Validity(mondayNoon); code != ReasonGrantRevoked || f.Level.ID != root.ID.UUID() {
		t.Fatalf("revoked ancestor: %s %+v", code, f)
	}
	if code, _ := (Chain{Grants: []Grant{root, child}}).Validity(issueTime.Add(13 * time.Hour)); code != ReasonGrantExpired {
		t.Fatalf("expired child: %s", code)
	}
	if code, _ := (Chain{Grants: []Grant{root, child}}).Validity(issueTime.Add(-time.Second)); code != ReasonGrantNotYetValid {
		t.Fatalf("not yet valid: %s", code)
	}
	if code, f := (Chain{Grants: []Grant{root, child}}).Validity(issueTime.Add(time.Hour)); code != "" || f != nil {
		t.Fatalf("valid chain: %s", code)
	}
}

func TestRequirementsAccumulateDownTheChain(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Requirements = []Requirement{{
		Operations: Ops{"payments.refund.create"}, Param: "amount",
		Unless:   &ParamBound{Max: Amounts{"USD": "50.00"}},
		Approval: &pdomain.ApprovalRequirement{Role: "refund_approver", Count: 1}, Reason: "REFUND_OVER_50",
	}}
	child := childOf(t, root, `{}`)
	child.Requirements = nil // a child cannot drop its parent's requirement
	chain := Chain{Grants: []Grant{root, child}}
	if rs := chain.Requirements(refund("30.00", "USD", "duplicate", mondayNoon)); len(rs) != 0 {
		t.Fatalf("a refund under the threshold needs nothing: %+v", rs)
	}
	for _, a := range []Action{
		refund("85.00", "USD", "duplicate", mondayNoon),
		refund("10.00", "EUR", "duplicate", mondayNoon), // another currency is not exempt
		func() Action { a := refund("1", "USD", "duplicate", mondayNoon); delete(a.Params, "amount"); return a }(),
	} {
		rs := chain.Requirements(a)
		if len(rs) != 1 || rs[0].Level.ID != root.ID.UUID() || rs[0].Requirement.Reason != "REFUND_OVER_50" {
			t.Fatalf("requirement not applied to %+v: %+v", a.Params, rs)
		}
	}
}

func TestEffectiveCaps(t *testing.T) {
	three, one := 3, 1
	week2 := 14 * 24 * time.Hour
	org := Envelope{Scope: Scope{Kind: ScopeOrg}, Settings: Settings{MaxDepth: &three, MaxRootLifetime: &week2}}
	team := Envelope{Scope: Scope{Kind: ScopeTeam, ID: ids.NewV7()}, Settings: Settings{MaxDepth: &one}}
	if c := EffectiveCaps(nil); c.MaxDepth != DefaultMaxDepth || c.MaxChildren != DefaultMaxChildren ||
		c.MaxRootLifetime != DefaultMaxRootLifetime || c.RepeatWindow != DefaultRepeatWindow {
		t.Fatalf("defaults: %+v", c)
	}
	if c := EffectiveCaps([]Envelope{org}); c.MaxDepth != 3 || c.MaxRootLifetime != week2 {
		t.Fatalf("the org raises its defaults: %+v", c)
	}
	if c := EffectiveCaps([]Envelope{team, org}); c.MaxDepth != 1 || c.MaxRootLifetime != week2 {
		t.Fatalf("a team only lowers: %+v", c)
	}
	five := 5
	teamUp := Envelope{Scope: Scope{Kind: ScopeTeam, ID: ids.NewV7()}, Settings: Settings{MaxDepth: &five}}
	if c := EffectiveCaps([]Envelope{teamUp}); c.MaxDepth != DefaultMaxDepth {
		t.Fatalf("a team cannot raise: %+v", c)
	}
}

func TestEnvelopeValidation(t *testing.T) {
	ok := orgEnvelope(t, refundBounds)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	five, hour := 5, time.Hour
	bad := map[string]func(e *Envelope){
		"depth over the hard cap": func(e *Envelope) { e.Settings.MaxDepth = &five },
		"repeat window on a team": func(e *Envelope) { e.Scope = Scope{Kind: ScopeTeam, ID: ids.NewV7()}; e.Settings.RepeatWindow = &hour },
		"repeat window too short": func(e *Envelope) { m := time.Minute; e.Settings.RepeatWindow = &m },
		"org scope with an id":    func(e *Envelope) { e.Scope.ID = ids.NewV7() },
		"team without an id":      func(e *Envelope) { e.Scope = Scope{Kind: ScopeTeam} },
		"principal workload": func(e *Envelope) {
			e.Scope = Scope{Kind: ScopePrincipal, Principal: Principal{Kind: PrincipalInstance, ID: ids.NewV7()}}
		},
		"bidi name":       func(e *Envelope) { e.Name = "org" + string(rune(0x202e)) },
		"bad requirement": func(e *Envelope) { e.Requirements = []Requirement{{Operations: Ops{"a.b"}, Reason: "X_Y_Z"}} },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			e := ok
			mutate(&e)
			if err := e.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestCompareDetectsWidening(t *testing.T) {
	cur := orgEnvelope(t, refundBounds)
	narrow := cur
	narrow.Revision = 2
	narrow.Bounds = mustBounds(t, `{"operations": ["payments.refund.get"]}`).Inherit(cur.Bounds)
	if c := Compare(cur, narrow); c.Widens {
		t.Fatalf("narrowing reported as widening: %s", c.Detail)
	}
	wide := cur
	wide.Bounds = mustBounds(t, `{"operations": ["payments.*"]}`)
	if c := Compare(cur, wide); !c.Widens {
		t.Fatal("widening not detected")
	}
	one := 1
	lower := cur
	lower.Settings.MaxDepth = &one
	if c := Compare(cur, lower); c.Widens {
		t.Fatalf("lowering a cap is not widening: %s", c.Detail)
	}
	if c := Compare(lower, cur); !c.Widens {
		t.Fatal("removing a cap is widening")
	}
	short := time.Hour
	shorter := cur
	shorter.Settings.RepeatWindow = &short
	if c := Compare(cur, shorter); !c.Widens {
		t.Fatal("a shorter repeat window weakens protection")
	}
}

func TestCompareRevision(t *testing.T) {
	cur := rootGrant(t, refundBounds)
	next := cur
	next.Revision = 2
	next.ExpiresAt = cur.ExpiresAt.Add(-time.Hour)
	if r, err := CompareRevision(cur, next); err != nil || r.Widens {
		t.Fatalf("an earlier expiry narrows: %+v %v", r, err)
	}
	next.ExpiresAt = cur.ExpiresAt.Add(time.Hour)
	if r, err := CompareRevision(cur, next); err != nil || !r.Widens {
		t.Fatalf("a later expiry widens: %+v %v", r, err)
	}
	next = cur
	next.Revision = 2
	next.AgentID = ids.NewV7()
	if _, err := CompareRevision(cur, next); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a revision moved the grant to another agent: %v", err)
	}
	next = cur
	next.Revision = 3
	if _, err := CompareRevision(cur, next); !errors.Is(err, ErrInvalid) {
		t.Fatal("a revision skipped a number")
	}
}

// TestHR046_ChainAllowsExactlyTheIntersection: evaluating every level one
// by one decides exactly like the intersection of all levels.
func TestHR046_ChainAllowsExactlyTheIntersection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 4).Draw(t, "levels")
		var chain Chain
		for i := range n {
			b := genBounds(t, "level")
			if rapid.Bool().Draw(t, "envelope") {
				chain.Envelopes = append(chain.Envelopes, Envelope{ID: NewEnvelopeID(), Revision: 1, Scope: Scope{Kind: scopeOrder[i%len(scopeOrder)]}, Bounds: b})
			} else {
				chain.Grants = append(chain.Grants, Grant{ID: NewGrantID(), Revision: 1, Bounds: b})
			}
		}
		eff := chain.Effective()
		for range 6 {
			a := genAction(t)
			perLevel := len(chain.Coverage(a)) == 0 && len(chain.Limits(a)) == 0
			if whole := eff.Check(a).Outcome == Allowed; perLevel != whole {
				t.Fatalf("per level %v, intersection %v for %+v", perLevel, whole, a)
			}
		}
	})
}

func TestVersionsFollowEvaluationOrder(t *testing.T) {
	root := rootGrant(t, refundBounds)
	child := childOf(t, root, `{}`)
	team := Envelope{ID: NewEnvelopeID(), Revision: 4, Scope: Scope{Kind: ScopeTeam, ID: ids.NewV7()}, Name: "payments"}
	org := orgEnvelope(t, `{}`)
	vs := (Chain{Envelopes: []Envelope{team, org}, Grants: []Grant{root, child}}).Versions()
	want := []string{org.ID.String(), team.ID.String(), root.ID.String(), child.ID.String()}
	var got []string
	for _, v := range vs {
		got = append(got, v.ID)
	}
	if !slices.Equal(got, want) || vs[1].Revision != 4 {
		t.Fatalf("versions %+v", vs)
	}
}

// TestHR045_DecodeRequirementsIsStrict: requirements arrive as JSON from the
// API; unknown members, duplicate keys and invalid requirements are refused,
// and empty input means none.
func TestHR045_DecodeRequirementsIsStrict(t *testing.T) {
	ok := `[{"operations": ["payments.refund.create"], "approval": {"role": "approver", "count": 1}, "reason": "REFUND_REVIEW"}]`
	rs, err := DecodeRequirements([]byte(ok))
	if err != nil || len(rs) != 1 || rs[0].Approval == nil || rs[0].Approval.Count != 1 {
		t.Fatalf("DecodeRequirements(valid) = %v, %v", rs, err)
	}
	if rs, err := DecodeRequirements(nil); err != nil || rs != nil {
		t.Fatalf("DecodeRequirements(empty) = %v, %v", rs, err)
	}
	for name, raw := range map[string]string{
		"unknown member": `[{"operations": ["payments.refund.create"], "approval": {"role": "approver", "count": 1}, "reason": "R_X", "x": 1}]`,
		"duplicate key":  `[{"operations": ["a.b"], "operations": ["c.d"], "approval": {"role": "approver", "count": 1}, "reason": "R_X"}]`,
		"no operations":  `[{"operations": [], "approval": {"role": "approver", "count": 1}, "reason": "R_X"}]`,
		"both kinds":     `[{"operations": ["a.b"], "approval": {"role": "approver", "count": 1}, "step_up": {"subject": "user", "method": "webauthn"}, "reason": "R_X"}]`,
		"bad reason":     `[{"operations": ["a.b"], "approval": {"role": "approver", "count": 1}, "reason": "lower"}]`,
		"not an array":   `{"operations": ["a.b"]}`,
	} {
		if _, err := DecodeRequirements([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
