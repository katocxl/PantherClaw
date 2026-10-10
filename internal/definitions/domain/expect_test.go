// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"maps"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// TestHR191_ExpectedValuesAreTheCanonicalActionFields: what a verifier must
// observe is computed from the (effective) action, in the forms a target
// reports, never from anything the target or the agent said.
func TestHR191_ExpectedValuesAreTheCanonicalActionFields(t *testing.T) {
	v := &domain.VerifierSpec{Expect: []domain.Expectation{
		{Field: "/charge", Equals: "target.id"},
		{Field: "/amount", Equals: "params.amount.value"},
		{Field: "/currency", Equals: "params.amount.currency"},
		{Field: "/reason", Equals: "params.reason"},
		{Field: "/count", Equals: "params.count"},
	}}
	amount, err := money.ParseMoney("30", "USD")
	if err != nil {
		t.Fatal(err)
	}
	vals := domain.Values{
		"amount": {Type: domain.TypeMoney, Money: amount},
		"reason": {Type: domain.TypeEnum, Str: "duplicate"},
		"count":  {Type: domain.TypeInteger, Int: 3},
	}
	got, ok := v.Expected(actionir.Target{Type: "payments.charge", ID: "ch_1"}, vals)
	want := map[string]string{"/charge": "ch_1", "/amount": "30.00", "/currency": "USD", "/reason": "duplicate", "/count": "3"}
	if !ok || !maps.Equal(got, want) {
		t.Fatalf("expected %v %v, want %v", got, ok, want)
	}
	delete(vals, "reason")
	if _, ok := v.Expected(actionir.Target{Type: "payments.charge", ID: "ch_1"}, vals); ok {
		t.Fatal("a missing value still gave expectations")
	}
	v.Expect = []domain.Expectation{{Field: "/note", Equals: "params.note"}}
	if _, ok := v.Expected(actionir.Target{}, domain.Values{"note": {Type: domain.TypeText, Str: "x"}}); ok {
		t.Fatal("untrusted text became an expectation")
	}
}
