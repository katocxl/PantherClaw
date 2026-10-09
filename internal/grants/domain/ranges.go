// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Range bounds an integer or decimal parameter: Min ≤ value ≤ Max, either
// end optional. Numbers are canonical decimal strings, never JSON numbers
// (HR-101). Unit, when given, must equal the definition's unit. Intersect
// can produce an empty range (Min > Max), which contains nothing.
type Range struct {
	Min  string `json:"min,omitzero"`
	Max  string `json:"max,omitzero"`
	Unit string `json:"unit,omitzero"`
}

func parseEnd(s string) (*money.Decimal, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // an absent end is unbounded
	}
	d, err := money.Parse(s)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r Range) ends() (lo, hi *money.Decimal, err error) {
	if lo, err = parseEnd(r.Min); err != nil {
		return nil, nil, err
	}
	hi, err = parseEnd(r.Max)
	return lo, hi, err
}

func (r Range) validate(name string) error {
	lo, hi, err := r.ends()
	if err != nil {
		return invalid("%s: %v", name, err)
	}
	if lo != nil && hi != nil && lo.Cmp(*hi) > 0 {
		return invalid("%s: min %s is above max %s", name, r.Min, r.Max)
	}
	if lo == nil && hi == nil {
		return invalid("%s: a range needs min, max or both", name)
	}
	return nil
}

// Contains reports whether v lies in the range. A range that does not parse
// contains nothing.
func (r Range) Contains(v money.Decimal) bool {
	lo, hi, err := r.ends()
	if err != nil {
		return false
	}
	return (lo == nil || lo.Cmp(v) <= 0) && (hi == nil || v.Cmp(*hi) <= 0)
}

func (r Range) empty() bool {
	lo, hi, err := r.ends()
	return err != nil || (lo != nil && hi != nil && lo.Cmp(*hi) > 0)
}

// Within reports whether r ⊆ p.
func (r Range) Within(p Range) bool {
	if r.empty() {
		return true
	}
	if r.Unit != p.Unit && r.Unit != "" && p.Unit != "" {
		return false
	}
	lo, hi, _ := r.ends()
	plo, phi, err := p.ends()
	if err != nil {
		return false
	}
	loOK := plo == nil || (lo != nil && plo.Cmp(*lo) <= 0)
	hiOK := phi == nil || (hi != nil && hi.Cmp(*phi) <= 0)
	return loOK && hiOK
}

// Intersect returns the overlap of r and p (possibly empty).
func (r Range) Intersect(p Range) Range {
	out := Range{Min: r.Min, Max: r.Max, Unit: r.Unit}
	if out.Unit == "" {
		out.Unit = p.Unit
	}
	lo, hi, err1 := r.ends()
	plo, phi, err2 := p.ends()
	if err1 != nil || err2 != nil || (r.Unit != "" && p.Unit != "" && r.Unit != p.Unit) {
		return Range{Min: "1", Max: "0", Unit: out.Unit} // empty
	}
	if plo != nil && (lo == nil || plo.Cmp(*lo) > 0) {
		out.Min = p.Min
	}
	if phi != nil && (hi == nil || phi.Cmp(*hi) < 0) {
		out.Max = p.Max
	}
	return out
}

// String renders the range for explanations.
func (r Range) String() string {
	unit := ""
	if r.Unit != "" {
		unit = " " + r.Unit
	}
	switch {
	case r.Min != "" && r.Max != "":
		return fmt.Sprintf("%s to %s%s", r.Min, r.Max, unit)
	case r.Max != "":
		return fmt.Sprintf("at most %s%s", r.Max, unit)
	default:
		return fmt.Sprintf("at least %s%s", r.Min, unit)
	}
}

// Amounts limits a money parameter per currency: each listed currency up to
// its maximum; a currency that is not listed is not allowed at all.
type Amounts map[string]string

func (a Amounts) limit(c money.Currency) (money.Money, bool) {
	s, ok := a[string(c)]
	if !ok {
		return money.Money{}, false
	}
	m, err := money.ParseMoney(s, string(c))
	return m, err == nil
}

func (a Amounts) validate(name string) error {
	if len(a) == 0 || len(a) > maxEntries {
		return invalid("%s: list 1..%d currencies", name, maxEntries)
	}
	for c, v := range a {
		m, err := money.ParseMoney(v, c)
		if err != nil {
			return invalid("%s: %v", name, err)
		}
		if m.Amount.Sign() < 0 {
			return invalid("%s: maximum %s %s is negative", name, v, c)
		}
	}
	return nil
}

// Contains reports whether m is within its currency's maximum.
func (a Amounts) Contains(m money.Money) bool {
	lim, ok := a.limit(m.Currency)
	if !ok {
		return false
	}
	c, err := m.Cmp(lim)
	return err == nil && c <= 0
}

// Within reports whether every currency of a is allowed by p with an equal
// or higher maximum.
func (a Amounts) Within(p Amounts) (string, bool) {
	for _, c := range slices.Sorted(maps.Keys(a)) {
		mine, ok1 := a.limit(money.Currency(c))
		theirs, ok2 := p.limit(money.Currency(c))
		if !ok1 {
			continue // an unparsable entry allows nothing
		}
		if !ok2 {
			return c, false
		}
		if cmp, err := mine.Cmp(theirs); err != nil || cmp > 0 {
			return c, false
		}
	}
	return "", true
}

// Intersect keeps the currencies both allow, at the lower maximum.
func (a Amounts) Intersect(p Amounts) Amounts {
	out := Amounts{}
	for c := range a {
		mine, ok1 := a.limit(money.Currency(c))
		theirs, ok2 := p.limit(money.Currency(c))
		if !ok1 || !ok2 {
			continue
		}
		if cmp, err := mine.Cmp(theirs); err == nil && cmp <= 0 {
			out[c] = a[c]
		} else {
			out[c] = p[c]
		}
	}
	return out
}

// String renders the limits for explanations.
func (a Amounts) String() string {
	if len(a) == 0 {
		return "no currency"
	}
	var parts []string
	for _, c := range slices.Sorted(maps.Keys(a)) {
		parts = append(parts, "at most "+a[c]+" "+c)
	}
	return strings.Join(parts, " or ")
}
