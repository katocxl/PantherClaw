// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The six F193 policy scenarios, each with its expected decision and
// decisive reason (F194). Scenario 6's resubmission part needs the
// finalization (idempotency) and is in the authority package.

func TestF193_1_ValidLookupIsAllowed(t *testing.T) {
	f := newFx(t)
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
}

func TestF193_2_UnrelatedLookupIsDenied(t *testing.T) {
	f := newFx(t)
	ev := f.call(f.run, "get_refund", `{"refund":"re_9"}`)
	expect(t, ev, adomain.Deny, gdomain.ReasonTargetNotGranted)
	if d := ev.Decisive(); !strings.Contains(d.Detail, "re_9") || !strings.Contains(d.Detail, "re_1") {
		t.Fatalf("the explanation names the target and what is permitted: %q", d.Detail)
	}
}

func TestF193_3_ApprovalThresholdHolds(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "50.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	ev := f.call(f.run, "create_refund", refund("ch_1", "85.00"))
	expect(t, ev, adomain.RequireApproval, "REFUND_OVER_50")
	if len(ev.Approvals) != 1 || ev.Approvals[0].Role != "finance.approver" {
		t.Fatalf("approvals %+v", ev.Approvals)
	}
}

func TestF193_4_GrantLimitDeniesEvenWhenPolicyWouldHold(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	ev := f.call(f.run, "create_refund", refund("ch_1", "125.00"))
	expect(t, ev, adomain.Deny, gdomain.ReasonGrantLimitExceeded)
	if !strings.Contains(ev.Decisive().Detail, "at most 100.00 USD") {
		t.Fatalf("the explanation gives the permitted alternative: %q", ev.Decisive().Detail)
	}
	held := false
	for _, it := range ev.Checklist {
		held = held || it.Code == "REFUND_OVER_50"
	}
	if !held {
		t.Fatal("the hold is still listed after the decisive denial")
	}
}

func TestF193_5_SplitBudgetIsPrevented(t *testing.T) {
	f := newFx(t)
	root := f.grant
	limits, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "100.00", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	root.Revision, root.Limits = 2, limits
	f.w.Grants.Put(root)

	first := f.call(f.run, "create_refund", refund("ch_1", "60.00"))
	expect(t, first, adomain.Allow, pipeline.ReasonGrantCovers)
	f.w.Reserve(first)

	// The second half comes from a child agent under a delegated grant and
	// a new run id: it still draws on the root's task budget (F059, F117).
	child := root
	child.ID, child.Revision, child.Parent, child.Depth = gdomain.NewGrantID(), 1, root.ID, 1
	child.Limits = gdomain.Limits{}
	child.ExpiresAt = now.Add(12 * time.Hour)
	child.Delegation = gdomain.Delegation{}
	f.w.Grants.Put(child)
	f.putFact("ch_2", true, now.Add(-time.Minute))
	ev := f.call(f.newRun(child.ID), "create_refund", refund("ch_2", "60.00"))
	expect(t, ev, adomain.Deny, gdomain.ReasonBudgetExhausted)
	if !strings.Contains(ev.Decisive().Detail, root.ID.String()) {
		t.Fatalf("the explanation names the ancestor's budget: %q", ev.Decisive().Detail)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "40.00")), adomain.Allow, pipeline.ReasonGrantCovers)
}

func TestF193_6_NarrowedGrantChangesTheDecisionBasis(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "85.00"))
	held := f.eval(req)
	expect(t, held, adomain.RequireApproval, "REFUND_OVER_50")

	narrowed := f.grant
	narrowed.Revision = 2
	narrowed.Bounds.Params = map[string]map[string]gdomain.ParamBound{"payments.refund.create": {"amount": {Max: gdomain.Amounts{"USD": "80.00"}}}}
	f.w.Grants.Put(narrowed)
	again := f.eval(req)
	expect(t, again, adomain.Deny, gdomain.ReasonGrantLimitExceeded)
	if again.Basis.Digest() == held.Basis.Digest() {
		t.Fatal("a narrowed grant left the decision basis unchanged, so an earlier approval could still match")
	}
}

func TestStep1_ScopeAndCoverage(t *testing.T) {
	f := newFx(t)
	req := f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Action.Action.Definition.Version = "9.9.9"
	expect(t, f.eval(req), adomain.CannotAuthorize, pipeline.ReasonDefinitionNotPinned)

	req = f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Action.Action.Route = "payments-refund" // the create route, for a read
	expect(t, f.eval(req), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)
}

func TestStep2_IdentityAndRunBinding(t *testing.T) {
	f := newFx(t)
	req := f.parse(ids.NewV7(), ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)

	req = f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Identity.AgentID = ids.NewV7()
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)

	req = f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Identity.InstanceID = ids.NewV7()
	f.w.AddRun(f.run, pipeline.Run{AgentID: f.agent, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env, GrantID: f.grant.ID, Active: true})
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonActionInstanceDiffer)

	g := f.grant
	g.Revision, g.MinAttestation = 2, 2
	f.w.Grants.Put(g)
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.CannotAuthorize, gdomain.ReasonAttestationTooLow)
}

func TestStep3_ContainmentDeniesAndProhibitionsWin(t *testing.T) {
	f := newFx(t)
	f.w.Cont.KillSwitch = true
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Deny, adomain.ReasonKillSwitch)
	// Missing evidence elsewhere does not turn a known prohibition into
	// CANNOT_AUTHORIZE: DENY is stricter (F092).
	expect(t, f.call(f.run, "create_refund", refund("ch_404", "10.00")), adomain.Deny, adomain.ReasonKillSwitch)
	f.w.Cont.KillSwitch = false

	f.w.SetState("payments.refund.get", defs.StateQuarantined)
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Deny, pipeline.ReasonPackageQuarantined)
	f.w.SetState("payments.refund.get", defs.StateActive)

	f.w.AddAgent(f.agent, pipeline.Agent{State: "SUSPENDED", TeamID: f.team})
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.Deny, pipeline.ReasonAgentSuspended)
}

func TestStep4_AuthorityOfEveryAncestor(t *testing.T) {
	f := newFx(t)
	expect(t, f.call(f.newRun(gdomain.GrantID{}), "get_refund", `{"refund":"re_1"}`), adomain.Deny, gdomain.ReasonNoGrant)

	child := f.grant
	child.ID, child.Revision, child.Parent, child.Depth = gdomain.NewGrantID(), 1, f.grant.ID, 1
	child.Bounds.Operations = &gdomain.Ops{"payments.*"} // wider than its parent, written around the checks
	f.w.Grants.Put(child)
	childRun := f.newRun(child.ID)
	ev := f.call(childRun, "create_refund", refund("ch_1", "100.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)

	revoked := f.grant
	revoked.State = gdomain.StateRevoked
	f.w.Grants.Put(revoked)
	expect(t, f.call(childRun, "get_refund", `{"refund":"re_1"}`), adomain.Deny, gdomain.ReasonGrantRevoked)

	expired := f.newGrant(grantBounds)
	expired.ExpiresAt = now.Add(-time.Second)
	f.w.Grants.Put(expired)
	expect(t, f.call(f.newRun(expired.ID), "get_refund", `{"refund":"re_1"}`), adomain.Deny, gdomain.ReasonGrantExpired)

	other := f.newGrant(grantBounds)
	other.Principal = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()}
	f.w.Grants.Put(other)
	expect(t, f.call(f.newRun(other.ID), "get_refund", `{"refund":"re_1"}`), adomain.Deny, gdomain.ReasonGrantMismatch)

	env := gdomain.Envelope{ID: gdomain.NewEnvelopeID(), Org: org, Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: f.team}, Name: "payments"}
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.get"]}`))
	env.Bounds = b
	if err := f.w.Grants.PutEnvelope(t.Context(), org, env, false, testEvent()); err != nil {
		t.Fatal(err)
	}
	fresh := f.newGrant(grantBounds)
	f.w.Grants.Put(fresh)
	expect(t, f.call(f.newRun(fresh.ID), "create_refund", refund("ch_1", "10.00")), adomain.Deny, gdomain.ReasonOutsideGuardrail)
}

func TestStep5_ExactMeaning(t *testing.T) {
	f := newFx(t)
	f.w.SetState("payments.refund.get", defs.StateReviewed)
	expect(t, f.call(f.run, "get_refund", `{"refund":"re_1"}`), adomain.CannotAuthorize, pipeline.ReasonDefinitionNotActive)
	f.w.SetState("payments.refund.get", defs.StateActive)

	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
	req.Action.Action.DedupeKey = "sha256:" + strings.Repeat("0", 64) // an agent-chosen key
	expect(t, f.eval(req), adomain.CannotAuthorize, adomain.ReasonAmbiguousInput)

	req = f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Action.Action.Target.ID = "ch_1" // a target the definition does not take
	expect(t, f.eval(req), adomain.CannotAuthorize, adomain.ReasonAmbiguousInput)
}

func TestHR160_FactsAreRequiredFreshAndFromProviders(t *testing.T) {
	f := newFx(t)
	expect(t, f.call(f.run, "create_refund", refund("ch_404", "10.00")), adomain.CannotAuthorize, fdomain.ReasonFactMissing)
	f.putFact("ch_old", true, now.Add(-10*time.Minute))
	expect(t, f.call(f.run, "create_refund", refund("ch_old", "10.00")), adomain.CannotAuthorize, fdomain.ReasonFactStale)

	// A FORBID on the fact denies once the fact is known.
	rule := pdomain.Rule{
		ID: "refundable-only", Kind: pdomain.Forbid, Summary: "only refundable charges",
		Operations: []string{"payments.refund.create"}, When: `!facts.payments_charge_refundable`, Reason: "NOT_REFUNDABLE",
	}
	if err := f.w.SetPolicy([]pdomain.Rule{rule}, map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}); err != nil {
		t.Fatal(err)
	}
	f.putFact("ch_no", false, now.Add(-time.Minute))
	expect(t, f.call(f.run, "create_refund", refund("ch_no", "10.00")), adomain.Deny, "NOT_REFUNDABLE")
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "10.00")), adomain.Allow, pipeline.ReasonGrantCovers)
}

func TestHR007_RepeatsAreParked(t *testing.T) {
	f := newFx(t)
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	key := f.eval(req).DedupeKey
	if key == "" {
		t.Fatal("an irreversible refund has a dedupe key")
	}
	f.w.SetClaim(key, pipeline.Claim{TransactionID: ids.NewV7(), State: pipeline.ClaimHeld, At: now})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, pipeline.ReasonReconciliation)
	f.w.SetClaim(key, pipeline.Claim{TransactionID: ids.NewV7(), State: pipeline.ClaimSucceeded, At: now.Add(-time.Hour)})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, pipeline.ReasonReconciliation)
	f.w.SetClaim(key, pipeline.Claim{TransactionID: ids.NewV7(), State: pipeline.ClaimSucceeded, At: now.Add(-25 * time.Hour)})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	f.w.SetClaim(key, pipeline.Claim{TransactionID: ids.NewV7(), State: pipeline.ClaimReleased, At: now})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	// Another amount is another action.
	f.w.SetClaim(key, pipeline.Claim{TransactionID: ids.NewV7(), State: pipeline.ClaimHeld, At: now})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "31.00")), adomain.Allow, pipeline.ReasonGrantCovers)
}

func TestGrantRequirementsHold(t *testing.T) {
	f := newFx(t)
	g := f.grant
	g.Revision = 2
	g.Requirements = []gdomain.Requirement{{
		Operations: gdomain.Ops{"payments.refund.create"}, Param: "amount", Unless: &gdomain.ParamBound{Max: gdomain.Amounts{"USD": "20.00"}},
		StepUp: &pdomain.StepUpRequirement{Subject: "principal", Method: "webauthn"}, Reason: "GRANT_STEP_UP_OVER_20",
	}}
	f.w.Grants.Put(g)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.RequireStepUp, "GRANT_STEP_UP_OVER_20")
	if len(ev.StepUps) != 1 {
		t.Fatalf("step-ups %+v", ev.StepUps)
	}
}

func TestEvidenceErrorsNeverAllow(t *testing.T) {
	for _, method := range []string{"Definition", "Policy", "Run", "Agent", "Chain", "Envelopes", "Facts", "Claim"} {
		t.Run(method, func(t *testing.T) {
			f := newFx(t)
			f.w.Fail[method] = true
			ev := f.call(f.run, "create_refund", refund("ch_1", "10.00"))
			if ev.Decision.Permits() {
				t.Fatalf("a failing %s still allowed the action", method)
			}
		})
	}
	f := newFx(t)
	f.w.Fail["Containment"] = true
	if _, err := f.p.Evaluate(t.Context(), f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)); err == nil {
		t.Fatal("without the database time there is no decision")
	}
}

func TestChecklistIsCompleteAndExplained(t *testing.T) {
	f := newFx(t)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	seen := map[int]bool{}
	for _, it := range ev.Checklist {
		seen[it.Step] = true
	}
	for step := pipeline.StepScope; step <= pipeline.StepRequirements; step++ {
		if !seen[step] {
			t.Errorf("step %d has no checklist item", step)
		}
	}
	if ev.Identity.Instance != f.instance.String() || ev.Identity.Principal != f.alice.String() {
		t.Fatalf("identity summary %+v", ev.Identity)
	}
	if len(ev.Basis.Levels) != 1 || ev.Basis.Levels[0].Revision != 1 || ev.Basis.Facts == "" || ev.Basis.Policy != "none" {
		t.Fatalf("basis %+v", ev.Basis)
	}
	if ev.Amount == nil || ev.Amount.String() != "30 USD" && ev.Amount.Amount.String() != "30" {
		t.Fatalf("amount %+v", ev.Amount)
	}
}

// TestF107_ClampingRecordsTheEffectiveAction: a CONSTRAIN rule whose limit
// the definition may clamp gives ALLOW_WITH_OBLIGATIONS, and the decision
// records the effective action's hash next to the requested one.
func TestF107_ClampingRecordsTheEffectiveAction(t *testing.T) {
	f := newFxWith(t, func(raw []byte) []byte {
		raw = bytes.Replace(raw, []byte("    effects:"), []byte("      batch:\n        type: integer\n        material: true\n        unit: count\n    effects:"), 1)
		return bytes.Replace(raw, []byte("      - kind: amount_max\n        param: amount\n"),
			[]byte("      - kind: amount_max\n        param: amount\n      - kind: count_max\n        param: batch\n        clamp: true\n"), 1)
	}, `            reason: input.reason
            batch: input.batch`)
	rule := pdomain.Rule{
		ID: "small-batches", Kind: pdomain.Constrain, Summary: "batches of at most 5",
		Operations: []string{"payments.refund.create"}, When: "true", Reason: "BATCH_LIMIT",
		Constraint: &pdomain.Constraint{Kind: pdomain.CountMax, Param: "batch", Max: "5"},
	}
	if err := f.w.SetPolicy([]pdomain.Rule{rule}, nil); err != nil {
		t.Fatal(err)
	}
	ev := f.call(f.run, "create_refund", `{"charge":"ch_1","amount":"10.00","currency":"USD","reason":"duplicate","batch":9}`)
	expect(t, ev, adomain.AllowWithObligations, "BATCH_LIMIT")
	if ev.EffectiveHash == ev.ActionHash || len(ev.Obligations) != 1 || !ev.Obligations[0].Clamp {
		t.Fatalf("effective %s requested %s obligations %+v", ev.EffectiveHash, ev.ActionHash, ev.Obligations)
	}
	small := f.call(f.run, "create_refund", `{"charge":"ch_1","amount":"10.00","currency":"USD","reason":"duplicate","batch":3}`)
	expect(t, small, adomain.Allow, pipeline.ReasonGrantCovers)
	if small.EffectiveHash != small.ActionHash {
		t.Fatal("an action within the limit is its own effective action")
	}
}
