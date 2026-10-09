// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

var catalog = map[string]fdomain.Type{
	"payments.charge.refundable":      fdomain.TypeBoolean,
	"payments.customer.bank_changed":  fdomain.TypeTimestamp,
	"payments.customer.lifetime_paid": fdomain.TypeMoney,
}

func (f *fixture) compileWithFacts(rules ...domain.Rule) (*Compiled, error) {
	e := &Engine{Limits: celenv.DefaultLimits, Facts: catalog}
	return e.Compile(&domain.Bundle{ID: "test", Version: 1, Rules: rules}, []*defs.Definition{f.def("payments.refund.create")})
}

var decisionTime = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// TestHR042_FactsAreDeclaredAndTyped: a rule reads only facts it declares
// and a provider declares, with the provider's type.
func TestHR042_FactsAreDeclaredAndTyped(t *testing.T) {
	f := newFixture(t)
	undeclared := refundRule("bank", domain.Forbid, `facts.payments_customer_bank_changed > now - 259200`)
	if _, err := f.compileWithFacts(undeclared); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a rule read a fact it does not declare: %v", err)
	}
	unknown := refundRule("unknown", domain.Forbid, `facts.payments_charge_frozen`)
	unknown.Facts = []domain.FactRef{{Name: "payments.charge.frozen", MaxAgeSeconds: 60}}
	if _, err := f.compileWithFacts(unknown); err == nil || !strings.Contains(err.Error(), "no provider declares") {
		t.Fatalf("a rule read a fact no provider supplies: %v", err)
	}
	mistyped := refundRule("typed", domain.Forbid, `facts.payments_customer_lifetime_paid > 5`)
	mistyped.Facts = []domain.FactRef{{Name: "payments.customer.lifetime_paid", MaxAgeSeconds: 60}}
	if _, err := f.compileWithFacts(mistyped); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a money fact compared with a number: %v", err)
	}
	// The definition's prerequisite is readable without a declaration.
	prereq := refundRule("prereq", domain.Forbid, `!facts.payments_charge_refundable`)
	if _, err := f.compileWithFacts(prereq); err != nil {
		t.Fatalf("a prerequisite fact: %v", err)
	}
	bad := refundRule("bad", domain.Forbid, `true`)
	bad.Facts = []domain.FactRef{{Name: "Payments.Charge", MaxAgeSeconds: 0}}
	if err := bad.Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("a malformed fact reference: %v", err)
	}
}

// TestHR160_MissingFactsAreNeverADenial: a rule whose facts are missing is
// not evaluated, and the result is CANNOT_AUTHORIZE even for a FORBID rule
// (F096); with the facts present it runs, and `now` gives review windows
// (F120).
func TestHR160_MissingFactsAreNeverADenial(t *testing.T) {
	f := newFixture(t)
	review := refundRule("bank-review", domain.RequireApproval, `facts.payments_customer_bank_changed > now - 259200`)
	review.Facts = []domain.FactRef{{Name: "payments.customer.bank_changed", MaxAgeSeconds: 300}}
	frozen := refundRule("not-refundable", domain.Forbid, `!facts.payments_charge_refundable`)
	c, err := f.compileWithFacts(review, frozen)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(facts map[string]fdomain.Value) domain.Outcome {
		t.Helper()
		out, err := c.Evaluate(context.Background(), f.def("payments.refund.create"), f.refund("30.00", "duplicate"),
			Input{Budget: DefaultBudget, Facts: facts, Now: decisionTime})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := eval(nil)
	if out.Verdict != domain.VerdictCannotAuthorize {
		t.Fatalf("missing facts gave %s, want CANNOT_AUTHORIZE", out.Verdict)
	}
	for _, it := range out.Checklist {
		if it.Status == domain.StatusFailed {
			t.Fatalf("a rule without its facts was reported as failed: %+v", it)
		}
	}
	if d, _ := out.Decisive(); d.Status != domain.StatusNotEvaluated || d.Reason != domain.ReasonFactMissing {
		t.Fatalf("decisive item %+v", d)
	}

	recent := fdomain.Value{Type: fdomain.TypeTimestamp, Int: decisionTime.Add(-24 * time.Hour).Unix()}
	old := fdomain.Value{Type: fdomain.TypeTimestamp, Int: decisionTime.Add(-96 * time.Hour).Unix()}
	yes := fdomain.Value{Type: fdomain.TypeBoolean, Bool: true}
	no := fdomain.Value{Type: fdomain.TypeBoolean, Bool: false}
	tests := []struct {
		name  string
		facts map[string]fdomain.Value
		want  domain.Verdict
	}{
		{"bank details changed yesterday", map[string]fdomain.Value{"payments.customer.bank_changed": recent, "payments.charge.refundable": yes}, domain.VerdictRequireApproval},
		{"bank details changed four days ago", map[string]fdomain.Value{"payments.customer.bank_changed": old, "payments.charge.refundable": yes}, domain.VerdictPass},
		{"not refundable", map[string]fdomain.Value{"payments.customer.bank_changed": old, "payments.charge.refundable": no}, domain.VerdictDeny},
		{"prerequisite present, review fact missing", map[string]fdomain.Value{"payments.charge.refundable": yes}, domain.VerdictCannotAuthorize},
	}
	for _, tt := range tests {
		if got := eval(tt.facts).Verdict; got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
	// A known prohibition still wins over missing evidence elsewhere.
	if got := eval(map[string]fdomain.Value{"payments.charge.refundable": no}).Verdict; got != domain.VerdictDeny {
		t.Fatalf("a FORBID with its facts present must deny even when another rule lacks facts: %s", got)
	}
}
