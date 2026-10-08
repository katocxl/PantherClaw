// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package money

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"pgregory.net/rapid"
)

func TestParseAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"0":                           "0",
		"85.00":                       "85",
		"85.50":                       "85.5",
		"-0.01":                       "-0.01",
		"100":                         "100",
		"999999999999999999.99999999": "999999999999999999.99999999",
		"0.00000001":                  "0.00000001",
		"-0":                          "0",
		"-0.00":                       "0",
	} {
		d, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if d.String() != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, d.String(), want)
		}
	}
}

func TestHR101_ParseRejectsNonCanonicalAmounts(t *testing.T) {
	for _, in := range []string{
		"", "-", ".", "1.", ".5", "+1", "01", "00", "-00", "-01", "1e3", "1E3", " 1", "1 ",
		"1,000", "1_000", "0x10", "NaN", "Inf", "-Inf", "١٢", // Arabic-Indic digits
		"1.000000001",         // 9 fraction digits
		"1000000000000000000", // 19 integer digits
		"1.0.0", "--1", "-+1", "1\x00",
	} {
		if _, err := Parse(in); !errors.Is(err, ErrInvalidDecimal) {
			t.Errorf("Parse(%q) err = %v, want ErrInvalidDecimal", in, err)
		}
	}
}

func TestArithmetic(t *testing.T) {
	a := MustParse("85.50")
	b := MustParse("14.5")
	sum, err := a.Add(b)
	if err != nil || sum.String() != "100" {
		t.Fatalf("85.50 + 14.5 = %v, %v", sum, err)
	}
	diff, err := b.Sub(a)
	if err != nil || diff.String() != "-71" {
		t.Fatalf("14.5 - 85.50 = %v, %v", diff, err)
	}
	prod, err := MustParse("0.1").MulInt(3)
	if err != nil || prod.String() != "0.3" {
		t.Fatalf("0.1 × 3 = %v, %v (floats would give 0.30000000000000004)", prod, err)
	}
	if a.Cmp(b) != 1 || b.Cmp(a) != -1 || a.Cmp(MustParse("85.5")) != 0 {
		t.Fatal("Cmp is wrong")
	}
	if !a.Neg().Neg().Equal(a) || a.Neg().Sign() != -1 {
		t.Fatal("Neg is wrong")
	}
	var zero Decimal
	if !zero.IsZero() || zero.String() != "0" || zero.Neg().String() != "0" {
		t.Fatal("zero value must behave as 0")
	}
}

func TestOverflowIsAnError(t *testing.T) {
	largest := MustParse("999999999999999999.99999999")
	if _, err := largest.Add(MustParse("0.00000001")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("max + 1 unit err = %v, want ErrOverflow", err)
	}
	if _, err := largest.Neg().Sub(MustParse("1")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("-max - 1 err = %v, want ErrOverflow", err)
	}
	if _, err := largest.MulInt(2); !errors.Is(err, ErrOverflow) {
		t.Fatalf("max × 2 err = %v, want ErrOverflow", err)
	}
}

func TestFromIntRange(t *testing.T) {
	d, err := FromInt(-42)
	if err != nil || d.String() != "-42" {
		t.Fatalf("FromInt(-42) = %v, %v", d, err)
	}
	if d, err := FromInt(999_999_999_999_999_999); err != nil || d.String() != "999999999999999999" {
		t.Fatalf("FromInt(18 nines) = %v, %v", d, err)
	}
	for _, n := range []int64{math.MaxInt64, math.MinInt64, 1_000_000_000_000_000_000} {
		if _, err := FromInt(n); !errors.Is(err, ErrOverflow) {
			t.Errorf("FromInt(%d) err = %v, want ErrOverflow", n, err)
		}
	}
	var s Decimal
	if err := s.Scan(int64(math.MaxInt64)); !errors.Is(err, ErrOverflow) {
		t.Errorf("Scan(MaxInt64) err = %v, want ErrOverflow", err)
	}
}

func TestStringFixed(t *testing.T) {
	s, err := MustParse("85.5").StringFixed(2)
	if err != nil || s != "85.50" {
		t.Fatalf("StringFixed(2) = %q, %v", s, err)
	}
	s, err = MustParse("100").StringFixed(0)
	if err != nil || s != "100" {
		t.Fatalf("StringFixed(0) = %q, %v", s, err)
	}
	if _, err := MustParse("85.001").StringFixed(2); err == nil {
		t.Fatal("StringFixed must not round 85.001 to 2 digits")
	}
}

func TestScanFromNumericColumn(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{"85.50000000", "85.5"},
		{[]byte("0.00"), "0"},
		{"-0.00000000", "0"},
		{"-12.30000000", "-12.3"},
		{int64(7), "7"},
	} {
		var d Decimal
		if err := d.Scan(c.in); err != nil || d.String() != c.want {
			t.Errorf("Scan(%v) = %q, %v; want %q", c.in, d.String(), err, c.want)
		}
	}
	var d Decimal
	if err := d.Scan(85.5); !errors.Is(err, ErrInvalidDecimal) {
		t.Fatalf("Scan(float64) err = %v, want ErrInvalidDecimal (floats are never accepted)", err)
	}
}

func TestTextRoundTrip(t *testing.T) {
	d := MustParse("-42.125")
	b, _ := d.MarshalText()
	var back Decimal
	if err := back.UnmarshalText(b); err != nil || !back.Equal(d) {
		t.Fatalf("round trip = %v, %v", back, err)
	}
	if err := back.UnmarshalText([]byte("4.2e1")); err == nil {
		t.Fatal("UnmarshalText accepted an exponent")
	}
}

// genDecimal draws decimals in the full PAP/1 range.
func genDecimal() *rapid.Generator[Decimal] {
	return rapid.Custom(func(t *rapid.T) Decimal {
		intPart := rapid.StringMatching(`0|[1-9][0-9]{0,17}`).Draw(t, "int")
		s := intPart
		if rapid.Bool().Draw(t, "hasFrac") {
			s += "." + rapid.StringMatching(`[0-9]{1,8}`).Draw(t, "frac")
		}
		if rapid.Bool().Draw(t, "neg") {
			s = "-" + s
		}
		d, err := Parse(s)
		if err != nil {
			// Unreachable for generated strings; keep the generator total.
			return Decimal{}
		}
		return d
	})
}

func toRat(d Decimal) *big.Rat {
	r, ok := new(big.Rat).SetString(d.String())
	if !ok {
		panic("bad decimal " + d.String())
	}
	return r
}

func TestPropDecimalMatchesExactRationals(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genDecimal().Draw(t, "a")
		b := genDecimal().Draw(t, "b")
		if got, want := a.Cmp(b), toRat(a).Cmp(toRat(b)); got != want {
			t.Fatalf("Cmp(%s, %s) = %d, rational says %d", a, b, got, want)
		}
		sum, err := a.Add(b)
		if err == nil {
			if want := new(big.Rat).Add(toRat(a), toRat(b)); toRat(sum).Cmp(want) != 0 {
				t.Fatalf("%s + %s = %s, want %s", a, b, sum, want.FloatString(8))
			}
			back, err := sum.Sub(b)
			if err != nil || !back.Equal(a) {
				t.Fatalf("(a+b)-b = %s, %v; want %s", back, err, a)
			}
		} else if !errors.Is(err, ErrOverflow) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

func TestPropParseFormatRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		d := genDecimal().Draw(t, "d")
		back, err := Parse(d.String())
		if err != nil || !back.Equal(d) || back.String() != d.String() {
			t.Fatalf("Parse(String(%s)) = %s, %v", d, back, err)
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"0", "85.50", "-1.5", "1e3", "01", "-0", "999999999999999999.99999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := Parse(s)
		if err != nil {
			return
		}
		r, ok := new(big.Rat).SetString(s)
		if !ok || r.Cmp(toRat(d)) != 0 {
			t.Fatalf("Parse(%q) = %s, which differs from the exact value", s, d)
		}
		if _, err := Parse(d.String()); err != nil {
			t.Fatalf("canonical form %q of %q does not re-parse: %v", d.String(), s, err)
		}
	})
}
