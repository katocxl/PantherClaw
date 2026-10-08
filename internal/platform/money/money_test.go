// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package money

import (
	"errors"
	"testing"
)

func TestParseMoney(t *testing.T) {
	m, err := ParseMoney("85.5", "USD")
	if err != nil {
		t.Fatal(err)
	}
	if m.String() != "85.50 USD" {
		t.Fatalf("String = %q", m.String())
	}
	if m, err := ParseMoney("100", "JPY"); err != nil || m.String() != "100 JPY" {
		t.Fatalf("JPY = %v, %v", m, err)
	}
}

func TestHR103_CurrencyIsNeverDefaulted(t *testing.T) {
	for _, c := range []string{"usd", "US", "USDX", "", "XXX", "BTC", "UЅD"} {
		if _, err := ParseCurrency(c); !errors.Is(err, ErrUnsupportedCurrency) {
			t.Errorf("ParseCurrency(%q) err = %v, want ErrUnsupportedCurrency", c, err)
		}
	}
	if _, err := New(MustParse("1"), Currency("XYZ")); !errors.Is(err, ErrUnsupportedCurrency) {
		t.Fatalf("New with unknown currency err = %v", err)
	}
}

func TestPrecisionBeyondMinorUnitRejected(t *testing.T) {
	for amount, cur := range map[string]string{"85.001": "USD", "1.5": "JPY", "0.0001": "KWD"} {
		if _, err := ParseMoney(amount, cur); !errors.Is(err, ErrPrecision) {
			t.Errorf("ParseMoney(%s, %s) err = %v, want ErrPrecision", amount, cur, err)
		}
	}
	if _, err := ParseMoney("0.001", "KWD"); err != nil {
		t.Fatalf("KWD has 3 minor digits: %v", err)
	}
}

func TestMoneyArithmeticRequiresSameCurrency(t *testing.T) {
	usd, _ := ParseMoney("10", "USD")
	eur, _ := ParseMoney("10", "EUR")
	if _, err := usd.Add(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("Add err = %v", err)
	}
	if _, err := usd.Sub(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("Sub err = %v", err)
	}
	if _, err := usd.Cmp(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("Cmp err = %v", err)
	}
	five, _ := ParseMoney("5", "USD")
	sum, err := usd.Add(five)
	if err != nil || sum.String() != "15.00 USD" {
		t.Fatalf("10 + 5 = %v, %v", sum, err)
	}
	diff, err := five.Sub(usd)
	if err != nil || diff.String() != "-5.00 USD" {
		t.Fatalf("5 - 10 = %v, %v", diff, err)
	}
	if c, err := five.Cmp(usd); err != nil || c != -1 {
		t.Fatalf("Cmp = %d, %v", c, err)
	}
}

func TestMinorUnitsTableIsUppercaseISO(t *testing.T) {
	for c, n := range minorUnits {
		if len(c) != 3 || n < 0 || n > 3 {
			t.Errorf("bad entry %q: %d", c, n)
		}
		for _, r := range c {
			if r < 'A' || r > 'Z' {
				t.Errorf("currency %q is not uppercase ASCII", c)
			}
		}
	}
}
