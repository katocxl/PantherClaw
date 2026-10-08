// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

func grant() DevGrant {
	limit, _ := money.ParseMoney("100", "USD")
	return DevGrant{Name: "dev-refunds", Operation: actionir.OpRefundCreate, MaxPerAction: limit, BudgetName: "dev-refunds"}
}

func action(t *testing.T, op, value, currency string) actionir.Parsed {
	t.Helper()
	a := actionir.ActionIR{
		V: 1, Org: "01920000-0000-7000-8000-00000000000a", Env: "01920000-0000-7000-8000-00000000000e",
		RunID: "01920000-0000-7000-8000-0000000000a1", ActionID: "01920000-0000-7000-8000-0000000000b1",
		AgentInstance: "01920000-0000-7000-8000-0000000000c1", Operation: op,
		Definition: actionir.Definition{
			Package: "pc.mock-payments", Version: "1.0.0",
			Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		},
		Channel: "http", Route: "payments-refund", Target: actionir.Target{Type: "payments.charge", ID: "ch_1"},
		Params: jsontext.Value(`{"amount":{"value":"` + value + `","currency":"` + currency + `"},"reason":"duplicate"}`),
	}
	p, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDevGrant(t *testing.T) {
	g := grant()
	cases := []struct {
		op, value, ccy string
		want           Decision
		reason         string
	}{
		{actionir.OpRefundCreate, "30.00", "USD", Allow, ReasonAllowedByGrant},
		{actionir.OpRefundCreate, "100.00", "USD", Allow, ReasonAllowedByGrant},
		{actionir.OpRefundCreate, "100.01", "USD", Deny, ReasonGrantAmountExceeded},
		{actionir.OpRefundCreate, "125.00", "USD", Deny, ReasonGrantAmountExceeded},
		{actionir.OpRefundCreate, "30.00", "EUR", Deny, ReasonGrantCurrency},
		{actionir.OpRefundCreate, "30.001", "USD", CannotAuthorize, ReasonAmbiguousInput},
		{"payments.charge.create", "30.00", "USD", Deny, ReasonNoGrant},
	}
	for _, c := range cases {
		o := g.Evaluate(action(t, c.op, c.value, c.ccy))
		if o.Decision != c.want || o.Decisive() != c.reason {
			t.Errorf("%s %s %s: %s/%s, want %s/%s", c.op, c.value, c.ccy, o.Decision, o.Decisive(), c.want, c.reason)
		}
		if o.Decision == Allow && o.Amount.String() != c.value+" USD" {
			t.Errorf("allowed amount = %s", o.Amount)
		}
	}
	if !Allow.Permits() || !AllowWithObligations.Permits() || Deny.Permits() || CannotAuthorize.Permits() || RequireApproval.Permits() {
		t.Fatal("Permits is wrong")
	}
}
