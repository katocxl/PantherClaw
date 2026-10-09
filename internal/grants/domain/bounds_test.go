// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"strings"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

const refundBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get"],
  "access": {"ids": ["read", "write"]},
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"prefixes": ["re_"]}},
  "params": {"payments.refund.create": {
    "amount": {"max": {"USD": "100.00"}},
    "reason": {"values": {"ids": ["duplicate", "fraudulent"]}}
  }},
  "weekly": [{"day": "mon", "from": "09:00", "to": "17:00"}]
}`

func mustBounds(t *testing.T, s string) Bounds {
	t.Helper()
	b, err := DecodeBounds([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func refund(amount, currency, reason string, at time.Time) Action {
	return Action{
		Operation: "payments.refund.create", Access: defs.AccessWrite,
		TargetType: "payments.charge", TargetID: "ch_1",
		Params: defs.Values{
			"amount": {Type: defs.TypeMoney, Money: money.Money{Amount: money.MustParse(amount), Currency: money.Currency(currency)}},
			"reason": {Type: defs.TypeEnum, Str: reason},
		},
		Time: at,
	}
}

var mondayNoon = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) // a Monday

func TestCheckExplainsTheOffendingValue(t *testing.T) {
	b := mustBounds(t, refundBounds)
	tests := []struct {
		name    string
		a       Action
		outcome Outcome
		dim     string
		detail  string
	}{
		{"within", refund("30.00", "USD", "duplicate", mondayNoon), Allowed, "", ""},
		{"over the maximum", refund("120.00", "USD", "duplicate", mondayNoon), Denied, "params.amount", "120.00 USD exceeds the bound; permitted: at most 100.00 USD"},
		{"currency not granted", refund("10.00", "EUR", "duplicate", mondayNoon), Denied, "params.amount", "permitted: at most 100.00 USD"},
		{"reason not granted", refund("10.00", "USD", "requested_by_customer", mondayNoon), Denied, "params.reason", "requested_by_customer is not allowed"},
		{"outside the window", refund("10.00", "USD", "duplicate", mondayNoon.Add(8*time.Hour)), Denied, "weekly", "Mon 20:00 UTC is outside"},
		{"operation not granted", func() Action {
			a := refund("1", "USD", "duplicate", mondayNoon)
			a.Operation = "payments.charge.create"
			return a
		}(), Denied, "operations", "payments.charge.create is not granted"},
		{"target not granted", func() Action { a := refund("1", "USD", "duplicate", mondayNoon); a.TargetID = "cus_1"; return a }(), Denied, "targets.payments.charge", "target cus_1 is not granted"},
		{"absent bounded param", func() Action {
			a := refund("1", "USD", "duplicate", mondayNoon)
			delete(a.Params, "reason")
			return a
		}(), Unknown, "params.reason", "absent"},
		{"param of another type", func() Action {
			a := refund("1", "USD", "duplicate", mondayNoon)
			a.Params["amount"] = defs.Value{Type: defs.TypeDecimal, Decimal: money.MustParse("1")}
			return a
		}(), Unknown, "params.amount", "cannot be checked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := b.Check(tt.a)
			if f.Outcome != tt.outcome || f.Dimension != tt.dim || !strings.Contains(f.Detail, tt.detail) {
				t.Fatalf("Check = %+v, want outcome %d dimension %q detail containing %q", f, tt.outcome, tt.dim, tt.detail)
			}
		})
	}
}

func TestHR103_AccountBoundNeedsAnAccount(t *testing.T) {
	b := mustBounds(t, `{"accounts": {"ids": ["acct_1"]}}`)
	a := refund("1", "USD", "duplicate", mondayNoon)
	if f := b.Check(a); f.Outcome != Allowed {
		t.Fatalf("a target without accounts is not limited by an account bound: %+v", f)
	}
	a.AccountDeclared = true
	if f := b.Check(a); f.Outcome != Unknown {
		t.Fatalf("an omitted account must not fall back to a default: %+v", f)
	}
	a.Account = "acct_2"
	if f := b.Check(a); f.Outcome != Denied {
		t.Fatalf("another account: %+v", f)
	}
	a.Account = "acct_1"
	if f := b.Check(a); f.Outcome != Allowed {
		t.Fatalf("the granted account: %+v", f)
	}
}

func TestHR045_WithinNamesTheWideningDimension(t *testing.T) {
	parent := mustBounds(t, refundBounds)
	readOnly := mustBounds(t, `{"access": {"ids": ["read"]}}`)
	tests := []struct {
		name, child string
		parent      Bounds
		inherit     bool
		dim         string
	}{
		{"more operations", `{"operations": ["payments.*"]}`, parent, true, "operations"},
		{"open where the parent is not", `{}`, parent, false, "operations"},
		{"write under a read-only parent", `{"access": {"ids": ["write"]}}`, readOnly, true, "access"},
		{"another target type", `{"targets": {"payments.customer": {"ids": ["cus_1"]}}}`, parent, true, "targets"},
		{"a wider target prefix", `{"targets": {"payments.charge": {"prefixes": ["c"]}}}`, parent, true, "targets.payments.charge"},
		{"a higher maximum", `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "100.01"}}}}}`, parent, true, "params.payments.refund.create.amount"},
		{"another currency", `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "1", "EUR": "1"}}}}}`, parent, true, "params.payments.refund.create.amount"},
		{"a longer window", `{"weekly": [{"day": "mon", "from": "08:00", "to": "17:00"}]}`, parent, true, "weekly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			child := mustBounds(t, tt.child)
			if tt.inherit {
				child = child.Inherit(tt.parent)
			}
			if v := child.Within(tt.parent); v == nil || v.Dimension != tt.dim {
				t.Fatalf("Within = %v, want a violation of %s", v, tt.dim)
			}
		})
	}
	narrower := mustBounds(t, `{"params": {"payments.refund.create": {"amount": {"max": {"USD": "50"}}}},
	  "targets": {"payments.charge": {"ids": ["ch_1"]}}}`).Inherit(parent)
	if v := narrower.Within(parent); v != nil {
		t.Fatalf("a narrower child is within its parent: %v", v)
	}
}

func TestHR100_BoundsAreStrict(t *testing.T) {
	bad := map[string]string{
		"duplicate key":     `{"operations": ["a.b"], "operations": ["a.c"]}`,
		"unknown field":     `{"operation": ["a.b"]}`,
		"null opens a dim":  `{"operations": null}`,
		"number amount":     `{"params": {"a.b": {"n": {"range": {"max": 5}}}}}`,
		"bad operation":     `{"operations": ["Payments.Refund"]}`,
		"bidi identifier":   `{"targets": {"t.a": {"ids": ["ch_` + string(rune(0x202e)) + `1"]}}}`,
		"two bound kinds":   `{"params": {"a.b": {"n": {"range": {"max": "5"}, "values": {"ids": ["x"]}}}}}`,
		"no bound kind":     `{"params": {"a.b": {"n": {}}}}`,
		"min above max":     `{"params": {"a.b": {"n": {"range": {"min": "5", "max": "1"}}}}}`,
		"bad currency":      `{"params": {"a.b": {"m": {"max": {"usd": "1"}}}}}`,
		"negative maximum":  `{"params": {"a.b": {"m": {"max": {"USD": "-1"}}}}}`,
		"window backwards":  `{"weekly": [{"day": "mon", "from": "17:00", "to": "09:00"}]}`,
		"unknown day":       `{"weekly": [{"day": "monday", "from": "09:00", "to": "17:00"}]}`,
		"bad access":        `{"access": {"ids": ["admin"]}}`,
		"access prefix":     `{"access": {"prefixes": ["r"]}}`,
		"empty params list": `{"params": {"a.b": {}}}`,
		"too deep":          `{"targets": {"t.a": {"ids": [[[[[[[[["x"]]]]]]]]]}}}`,
		"not an object":     `[]`,
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBounds([]byte(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("DecodeBounds(%s) = %v, want ErrInvalid", doc, err)
			}
		})
	}
	if _, err := DecodeBounds([]byte(strings.Repeat(" ", MaxBoundsBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized document accepted")
	}
}

func TestBoundsRoundTripCanonically(t *testing.T) {
	b := mustBounds(t, refundBounds)
	enc, err := EncodeBounds(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeBounds(enc)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := EncodeBounds(again)
	if string(enc) != string(enc2) {
		t.Fatalf("encoding is not stable:\n%s\n%s", enc, enc2)
	}
	if v := again.Within(b); v != nil {
		t.Fatalf("round trip changed meaning: %v", v)
	}
}

func refundDefinition() *defs.Definition {
	return &defs.Definition{Operation: "payments.refund.create", Params: map[string]defs.ParamSpec{
		"amount": {Type: defs.TypeMoney, Material: true, Required: true, Currencies: []string{"USD", "EUR"}},
		"reason": {Type: defs.TypeEnum, Material: true, Required: true, Values: []string{"duplicate", "fraudulent", "requested_by_customer"}},
		"limit":  {Type: defs.TypeInteger, Material: true, Unit: "records"},
		"note":   {Type: defs.TypeText},
	}}
}

func TestTypeCheckAgainstTheDefinition(t *testing.T) {
	lookup := func(op string) *defs.Definition {
		if op == "payments.refund.create" {
			return refundDefinition()
		}
		return nil
	}
	if err := mustBounds(t, refundBounds).TypeCheck(lookup); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"unknown operation": `{"params": {"payments.charge.create": {"amount": {"max": {"USD": "1"}}}}}`,
		"unknown param":     `{"params": {"payments.refund.create": {"fee": {"max": {"USD": "1"}}}}}`,
		"text param":        `{"params": {"payments.refund.create": {"note": {"values": {"ids": ["x"]}}}}}`,
		"range on money":    `{"params": {"payments.refund.create": {"amount": {"range": {"max": "1"}}}}}`,
		"unaccepted ccy":    `{"params": {"payments.refund.create": {"amount": {"max": {"GBP": "1"}}}}}`,
		"unknown enum":      `{"params": {"payments.refund.create": {"reason": {"values": {"ids": ["chargeback"]}}}}}`,
		"enum prefix":       `{"params": {"payments.refund.create": {"reason": {"values": {"prefixes": ["dup"]}}}}}`,
		"wrong unit":        `{"params": {"payments.refund.create": {"limit": {"range": {"max": "5", "unit": "rows"}}}}}`,
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if err := mustBounds(t, doc).TypeCheck(lookup); !errors.Is(err, ErrInvalid) {
				t.Fatalf("TypeCheck(%s) = %v, want ErrInvalid", doc, err)
			}
		})
	}
}

func FuzzGrantBounds(f *testing.F) {
	f.Add([]byte(refundBounds), []byte(`{"operations": ["payments.*"]}`))
	f.Add([]byte(`{"targets": {"t.a": {"prefixes": ["a/"]}}}`), []byte(`{"weekly": [{"day": "sun", "from": "00:00", "to": "24:00"}]}`))
	f.Fuzz(func(t *testing.T, x, y []byte) {
		a, err1 := DecodeBounds(x)
		b, err2 := DecodeBounds(y)
		if err1 != nil || err2 != nil {
			return
		}
		ab := a.Intersect(b)
		_ = ab.Within(a.Inherit(b))
		_ = a.Within(b)
		enc, err := EncodeBounds(a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeBounds(enc); err != nil {
			t.Fatalf("a valid document does not survive its own encoding: %v\n%s", err, enc)
		}
	})
}
