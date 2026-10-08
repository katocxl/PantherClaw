// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// richDefinition declares one param of every type.
func richDefinition() *Definition {
	d := create(refundPackage())
	d.Params["limit"] = ParamSpec{Type: TypeInteger, Unit: "rows", Min: "1", Max: "1000"}
	d.Params["ratio"] = ParamSpec{Type: TypeDecimal, Unit: "percent", Min: "0", Max: "100"}
	d.Params["notify"] = ParamSpec{Type: TypeBoolean}
	d.Params["branch"] = ParamSpec{Type: TypeIdentifier, Pattern: `^[a-z0-9/_-]+$`, MaxLength: 64}
	d.Params["labels"] = ParamSpec{Type: TypeIdentifierList, MaxItems: 3}
	return d
}

func decode(t *testing.T, d *Definition, raw string) (Values, error) {
	t.Helper()
	return d.DecodeParams([]byte(raw))
}

func TestParamsRoundTrip(t *testing.T) {
	d := richDefinition()
	raw := `{"amount":{"value":"85.50","currency":"USD"},"reason":"duplicate","note":"customer asked\ntwice",` +
		`"limit":"10","ratio":"12.5","notify":true,"branch":"release/1","labels":["a","b"]}`
	v, err := decode(t, d, raw)
	if err != nil {
		t.Fatal(err)
	}
	if v["amount"].Money.String() != "85.50 USD" || v["limit"].Int != 10 || v["ratio"].Decimal.String() != "12.5" ||
		!v["notify"].Bool || v["branch"].Str != "release/1" || len(v["labels"].List) != 2 {
		t.Fatalf("decoded %+v", v)
	}
	enc, err := d.EncodeParams(v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.DecodeParams(enc)
	if err != nil || !reflect.DeepEqual(again, v) {
		t.Fatalf("round trip: %v %+v", err, again)
	}
}

func TestPropParamsEncodeDecode(t *testing.T) {
	d := richDefinition()
	rapid.Check(t, func(t *rapid.T) {
		cents := rapid.Int64Range(1, 10_000_000).Draw(t, "cents")
		amount, err := money.MustParse("0.01").MulInt(cents)
		if err != nil {
			t.Fatal(err)
		}
		vals := Values{
			"amount": {Type: TypeMoney, Money: money.Money{Amount: amount, Currency: "EUR"}},
			"reason": {Type: TypeEnum, Str: rapid.SampledFrom([]string{"duplicate", "fraudulent"}).Draw(t, "reason")},
			"limit":  {Type: TypeInteger, Int: rapid.Int64Range(1, 1000).Draw(t, "limit")},
		}
		enc, err := d.EncodeParams(vals)
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.DecodeParams(enc)
		if err != nil {
			t.Fatal(err)
		}
		for k := range vals {
			if got[k].Type != vals[k].Type || got[k].Int != vals[k].Int || got[k].Str != vals[k].Str ||
				!got[k].Money.Amount.Equal(vals[k].Money.Amount) {
				t.Fatalf("%s: got %+v want %+v", k, got[k], vals[k])
			}
		}
	})
}

func wantAmbiguous(t *testing.T, d *Definition, cases map[string]string) {
	t.Helper()
	for name, raw := range cases {
		if _, err := decode(t, d, raw); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %s: err = %v, want ErrAmbiguous", name, raw, err)
		}
	}
}

const reason = `"reason":"duplicate"`

func TestHR100_ParamsAreStrictJSON(t *testing.T) {
	wantAmbiguous(t, richDefinition(), map[string]string{
		"duplicate key":          `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,` + reason + `}`,
		"duplicate money member": `{"amount":{"value":"1.00","value":"2.00","currency":"USD"},` + reason + `}`,
		"unknown money member":   `{"amount":{"value":"1.00","currency":"USD","fx":"1"},` + reason + `}`,
		"not an object":          `[]`,
		"null":                   `null`,
	})
}

func TestHR101_AmountsAreCanonicalDecimalStrings(t *testing.T) {
	amount := func(v string) string { return `{"amount":{"value":` + v + `,"currency":"USD"},` + reason + `}` }
	if _, err := decode(t, richDefinition(), amount(`"85.50"`)); err != nil {
		t.Fatal(err)
	}
	wantAmbiguous(t, richDefinition(), map[string]string{
		"JSON number":            amount(`85.5`),
		"not minor units":        amount(`"85.5"`),
		"too precise":            amount(`"85.501"`),
		"exponent":               amount(`"8.55e1"`),
		"leading zero":           amount(`"085.50"`),
		"zero":                   amount(`"0.00"`),
		"negative":               amount(`"-1.00"`),
		"above max":              amount(`"100000.01"`),
		"integer as number":      `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"limit":10}`,
		"integer with fraction":  `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"limit":"10.0"}`,
		"non-canonical decimal":  `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"ratio":"12.50"}`,
		"boolean as string":      `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"notify":"true"}`,
		"integer below minimum":  `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"limit":"0"}`,
		"integer above maximum":  `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"limit":"1001"}`,
		"integer beyond int64":   `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"limit":"99999999999999999999"}`,
		"lowercase currency":     `{"amount":{"value":"1.00","currency":"usd"},` + reason + `}`,
		"currency not supported": `{"amount":{"value":"1.00","currency":"GBP"},` + reason + `}`,
	})
}

func TestHR102_ParamStringsRejectConfusablesAndControls(t *testing.T) {
	base := `{"amount":{"value":"1.00","currency":"USD"},` + reason
	rlo := string(rune(0x202e))
	wantAmbiguous(t, richDefinition(), map[string]string{
		"bidi in text":           base + `,"note":"refund ` + rlo + `ok"}`,
		"control in text":        base + `,"note":"a\u0007b"}`,
		"zero width in text":     base + `,"note":"a` + string(rune(0x200b)) + `b"}`,
		"cyrillic identifier":    base + `,"branch":"m` + string(rune(0x0430)) + `in"}`,
		"space in identifier":    base + `,"branch":"main branch"}`,
		"identifier pattern":     base + `,"branch":"Main"}`,
		"identifier too long":    base + `,"branch":"` + longText(65) + `"}`,
		"duplicate list item":    base + `,"labels":["a","a"]}`,
		"too many list items":    base + `,"labels":["a","b","c","d"]}`,
		"non-identifier in list": base + `,"labels":["a b"]}`,
		"text too long":          base + `,"note":"` + longText(501) + `"}`,
	})
}

func longText(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

func TestHR103_ParamsAreNeverDefaulted(t *testing.T) {
	wantAmbiguous(t, richDefinition(), map[string]string{
		"missing amount":    `{` + reason + `}`,
		"missing reason":    `{"amount":{"value":"1.00","currency":"USD"}}`,
		"missing currency":  `{"amount":{"value":"1.00"},` + reason + `}`,
		"unknown param":     `{"amount":{"value":"1.00","currency":"USD"},` + reason + `,"priority":"high"}`,
		"unsupported value": `{"amount":{"value":"1.00","currency":"USD"},"reason":"because"}`,
	})
	d := richDefinition()
	if _, err := d.EncodeParams(Values{"reason": {Type: TypeIdentifier, Str: "duplicate"}}); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("encoding a value of the wrong type: %v", err)
	}
}

func TestHR007_DedupeKeyIsCanonical(t *testing.T) {
	d := richDefinition()
	target := actionir.Target{Type: "payments.charge", ID: "ch_1"}
	key := func(raw string) string {
		t.Helper()
		v, err := decode(t, d, raw)
		if err != nil {
			t.Fatal(err)
		}
		k, err := d.DedupeKey(target, v)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	a := key(`{"amount":{"value":"30.00","currency":"USD"},"reason":"duplicate"}`)
	if err := actionir.CheckIdentifier("dedupe_key", a); err != nil || len(a) != len("sha256:")+64 {
		t.Fatalf("key %q: %v", a, err)
	}
	// Fields outside the key (reason, note) do not change it.
	if b := key(`{"amount":{"value":"30.00","currency":"USD"},"reason":"fraudulent","note":"again"}`); b != a {
		t.Fatal("fields outside the dedupe key changed it")
	}
	if c := key(`{"amount":{"value":"30.01","currency":"USD"},"reason":"duplicate"}`); c == a {
		t.Fatal("a different amount must give a different key")
	}
	other := *d
	other.Operation = "payments.refund.retry"
	v, _ := decode(t, d, `{"amount":{"value":"30.00","currency":"USD"},"reason":"duplicate"}`)
	if k, _ := other.DedupeKey(target, v); k == a {
		t.Fatal("keys of different operations must differ")
	}
	if _, err := d.DedupeKey(target, Values{}); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("missing key field: %v", err)
	}
	if _, err := d.DedupeKey(actionir.Target{Type: "payments.charge"}, v); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("missing target id: %v", err)
	}
}
