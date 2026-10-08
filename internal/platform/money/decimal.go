// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package money provides exact decimal amounts for material parameters,
// budgets and limits. Floats are never used for money (BUILD_GUIDE §3.1,
// HR-041, HR-101).
//
// A Decimal has at most 18 integer digits and 8 fraction digits, matching the
// PAP/1 amount grammar ^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$ (PAP-1 §6).
// Arithmetic is exact; results outside that range are errors, never rounded.
package money

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	// MaxIntDigits is the maximum number of integer digits.
	MaxIntDigits = 18
	// MaxScale is the maximum number of fraction digits.
	MaxScale = 8
)

var (
	// ErrInvalidDecimal reports a string outside the PAP/1 amount grammar.
	ErrInvalidDecimal = errors.New("money: invalid decimal")
	// ErrOverflow reports a result outside the representable range.
	ErrOverflow = errors.New("money: decimal overflow")
)

var (
	scaleFactor = new(big.Int).Exp(big.NewInt(10), big.NewInt(MaxScale), nil)
	// maxUnits is the largest magnitude in units of 10^-MaxScale.
	maxUnits = new(big.Int).Sub(new(big.Int).Exp(big.NewInt(10), big.NewInt(MaxIntDigits+MaxScale), nil), big.NewInt(1))
)

// Decimal is an exact decimal number. The zero value is 0. Decimals are
// immutable: every operation returns a new value.
type Decimal struct {
	units *big.Int // value × 10^MaxScale; nil means zero
}

// Parse parses a decimal string in the PAP/1 amount grammar
// ^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$ exactly. Leading zeros, a leading
// '+', exponents, whitespace and more than 8 fraction digits are rejected.
// "-0" is accepted (the grammar allows it) and equals zero.
func Parse(s string) (Decimal, error) {
	if len(s) == 0 || len(s) > 1+MaxIntDigits+1+MaxScale {
		return Decimal{}, invalid(s)
	}
	body := s
	neg := false
	if body[0] == '-' {
		neg = true
		body = body[1:]
	}
	intPart, fracPart, hasDot := strings.Cut(body, ".")
	if !allDigits(intPart) || len(intPart) == 0 || len(intPart) > MaxIntDigits ||
		(len(intPart) > 1 && intPart[0] == '0') {
		return Decimal{}, invalid(s)
	}
	if hasDot && (len(fracPart) == 0 || len(fracPart) > MaxScale || !allDigits(fracPart)) {
		return Decimal{}, invalid(s)
	}
	digits := intPart + fracPart + strings.Repeat("0", MaxScale-len(fracPart))
	units, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return Decimal{}, invalid(s)
	}
	if neg {
		// "-0" and "-0.00" match the PAP/1 grammar; they denote zero.
		units.Neg(units)
	}
	return fromUnits(units), nil
}

// MustParse is Parse for constants in tests and static tables; it panics on
// invalid input.
func MustParse(s string) Decimal {
	d, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

// FromInt returns the decimal value of n, or ErrOverflow when n has more than
// 18 digits.
func FromInt(n int64) (Decimal, error) {
	return checked(new(big.Int).Mul(big.NewInt(n), scaleFactor))
}

func fromUnits(u *big.Int) Decimal {
	if u.Sign() == 0 {
		return Decimal{}
	}
	return Decimal{units: u}
}

func invalid(s string) error {
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	return fmt.Errorf("%w: %q", ErrInvalidDecimal, s)
}

func allDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (d Decimal) u() *big.Int {
	if d.units == nil {
		return new(big.Int)
	}
	return d.units
}

// String returns the shortest canonical form: no trailing fraction zeros and
// no decimal point for integers ("85.5", "100", "-0.01").
func (d Decimal) String() string {
	u := d.u()
	if u.Sign() == 0 {
		return "0"
	}
	abs := new(big.Int).Abs(u)
	q, r := new(big.Int).QuoRem(abs, scaleFactor, new(big.Int))
	var b strings.Builder
	if u.Sign() < 0 {
		b.WriteByte('-')
	}
	b.WriteString(q.String())
	if r.Sign() != 0 {
		frac := fmt.Sprintf("%0*s", MaxScale, r.String())
		b.WriteByte('.')
		b.WriteString(strings.TrimRight(frac, "0"))
	}
	return b.String()
}

// StringFixed formats with exactly scale fraction digits. It returns an error
// if the value has more significant fraction digits than scale (no rounding).
func (d Decimal) StringFixed(scale int) (string, error) {
	if scale < 0 || scale > MaxScale {
		return "", fmt.Errorf("money: scale %d out of range", scale)
	}
	if d.Scale() > scale {
		return "", fmt.Errorf("%w: %s has more than %d fraction digits", ErrInvalidDecimal, d, scale)
	}
	s := d.String()
	intPart, frac, _ := strings.Cut(s, ".")
	if scale == 0 {
		return intPart, nil
	}
	return intPart + "." + frac + strings.Repeat("0", scale-len(frac)), nil
}

// Scale returns the number of significant fraction digits (0 for integers).
func (d Decimal) Scale() int {
	_, frac, _ := strings.Cut(d.String(), ".")
	return len(frac)
}

// Sign returns -1, 0 or +1.
func (d Decimal) Sign() int { return d.u().Sign() }

// IsZero reports whether d is zero.
func (d Decimal) IsZero() bool { return d.Sign() == 0 }

// Cmp compares d and e: -1 if d < e, 0 if equal, +1 if d > e.
func (d Decimal) Cmp(e Decimal) int { return d.u().Cmp(e.u()) }

// Equal reports whether d and e have the same value.
func (d Decimal) Equal(e Decimal) bool { return d.Cmp(e) == 0 }

// Neg returns -d.
func (d Decimal) Neg() Decimal { return fromUnits(new(big.Int).Neg(d.u())) }

// Add returns d + e, or ErrOverflow.
func (d Decimal) Add(e Decimal) (Decimal, error) {
	return checked(new(big.Int).Add(d.u(), e.u()))
}

// Sub returns d - e, or ErrOverflow.
func (d Decimal) Sub(e Decimal) (Decimal, error) {
	return checked(new(big.Int).Sub(d.u(), e.u()))
}

// MulInt returns d × n, or ErrOverflow.
func (d Decimal) MulInt(n int64) (Decimal, error) {
	return checked(new(big.Int).Mul(d.u(), big.NewInt(n)))
}

func checked(u *big.Int) (Decimal, error) {
	if new(big.Int).Abs(u).Cmp(maxUnits) > 0 {
		return Decimal{}, ErrOverflow
	}
	return fromUnits(u), nil
}

// MarshalText implements encoding.TextMarshaler: amounts are always strings
// on the wire, never JSON numbers (HR-101).
func (d Decimal) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler using Parse.
func (d *Decimal) UnmarshalText(b []byte) error {
	v, err := Parse(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// Value implements driver.Valuer for numeric(26,8) columns.
func (d Decimal) Value() (driver.Value, error) { return d.String(), nil }

// Scan implements sql.Scanner for numeric columns. Postgres renders numeric
// with its column scale ("85.50000000"), so trailing fraction zeros beyond
// the 8-digit limit are tolerated here, unlike in Parse.
func (d *Decimal) Scan(src any) error {
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	case int64:
		v2, err := FromInt(v)
		if err != nil {
			return err
		}
		*d = v2
		return nil
	default:
		return fmt.Errorf("%w: cannot scan %T", ErrInvalidDecimal, src)
	}
	if intPart, frac, ok := strings.Cut(s, "."); ok {
		frac = strings.TrimRight(frac, "0")
		s = intPart
		if frac != "" {
			s += "." + frac
		}
	}
	if s == "-0" {
		s = "0"
	}
	return d.UnmarshalText([]byte(s))
}
