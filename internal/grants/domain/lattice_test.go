// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// The generators use tiny alphabets so that sets overlap often. 'z' never
// appears in generated sets, so appending it builds a value no generated
// prefix or id covers: that is how the completeness checks find witnesses.

func genWord(t *rapid.T, label string) string {
	return rapid.StringOfN(rapid.SampledFrom([]rune("ab/")), 1, 3, -1).Draw(t, label)
}

func genMatch(t *rapid.T, label string) Match {
	return Match{
		IDs:      rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return genWord(t, "id") }), 0, 3).Draw(t, label+".ids"),
		Prefixes: rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return genWord(t, "prefix") }), 0, 3).Draw(t, label+".prefixes"),
	}
}

// probes returns values around every entry of the given sets.
func probes(t *rapid.T, sets ...Match) []string {
	out := []string{genWord(t, "probe"), "", "z"}
	for _, m := range sets {
		for _, v := range append(append([]string{}, m.IDs...), m.Prefixes...) {
			out = append(out, v, v+"a", v+"b", v+"/", v+"z", v[:len(v)-1])
		}
	}
	return out
}

// witness finds a value m allows and p refuses, if one exists among the
// candidates that completeness needs: an uncovered id itself, or an
// uncovered prefix q (q, or q+"z" when p happens to list q as an id).
func witness(m, p Match) (string, bool) {
	for _, id := range m.IDs {
		if !p.Matches(id) {
			return id, true
		}
	}
	for _, q := range m.Prefixes {
		for _, v := range []string{q, q + "z"} {
			if m.Matches(v) && !p.Matches(v) {
				return v, true
			}
		}
	}
	return "", false
}

func TestHR045_MatchSubsetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genMatch(t, "child"), genMatch(t, "parent")
		_, within := c.Within(p)
		v, found := witness(c, p)
		if within && found {
			t.Fatalf("Within(%v, %v) but %q is allowed by the child only", c, p, v)
		}
		if !within && !found {
			t.Fatalf("not Within(%v, %v), but no value separates them (the test is not exact)", c, p)
		}
		for _, v := range probes(t, c, p) {
			if within && c.Matches(v) && !p.Matches(v) {
				t.Fatalf("Within(%v, %v) is unsound at %q", c, p, v)
			}
		}
	})
}

func TestHR045_MatchIntersectIsTheMeet(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := genMatch(t, "a"), genMatch(t, "b"), genMatch(t, "c")
		ab := a.Intersect(b)
		if _, ok := ab.Within(a); !ok {
			t.Fatalf("a∩b ⊄ a: %v, %v", ab, a)
		}
		if _, ok := ab.Within(b); !ok {
			t.Fatalf("a∩b ⊄ b: %v, %v", ab, b)
		}
		for _, v := range probes(t, a, b, c) {
			if got, want := ab.Matches(v), a.Matches(v) && b.Matches(v); got != want {
				t.Fatalf("(%v ∩ %v).Matches(%q) = %v, want %v", a, b, v, got, want)
			}
			if b.Intersect(a).Matches(v) != ab.Matches(v) {
				t.Fatalf("intersection is not commutative at %q", v)
			}
			if a.Intersect(a).Matches(v) != a.Matches(v) {
				t.Fatalf("intersection is not idempotent at %q", v)
			}
			if ab.Intersect(c).Matches(v) != a.Intersect(b.Intersect(c)).Matches(v) {
				t.Fatalf("intersection is not associative at %q", v)
			}
		}
		// Any common lower bound is within the meet.
		if _, ok1 := c.Within(a); ok1 {
			if _, ok2 := c.Within(b); ok2 {
				if _, ok := c.Within(ab); !ok {
					t.Fatalf("%v is within %v and %v but not their meet %v", c, a, b, ab)
				}
			}
		}
	})
}

func genOps(t *rapid.T, label string) Ops {
	seg := rapid.SampledFrom([]string{"a", "b"})
	return Ops(rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "prefix") {
			s := seg.Draw(t, "s1")
			if rapid.Bool().Draw(t, "deep") {
				s += "." + seg.Draw(t, "s2")
			}
			return s + ".*"
		}
		s := seg.Draw(t, "s1") + "." + seg.Draw(t, "s2")
		if rapid.Bool().Draw(t, "deep") {
			s += "." + seg.Draw(t, "s3")
		}
		return s
	}), 0, 3).Draw(t, label))
}

func opProbes(sets ...Ops) []string {
	out := []string{"a.z", "z.z"}
	for _, o := range sets {
		for _, p := range o {
			if pre, ok := opPrefix(p); ok {
				out = append(out, pre+"z", pre+"a", pre+"a.b", pre+"b.a")
			} else {
				out = append(out, p, p+".z")
			}
		}
	}
	return out
}

func TestHR045_OperationSubsetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genOps(t, "child"), genOps(t, "parent")
		_, within := c.Within(p)
		separated := false
		for _, op := range opProbes(c, p) {
			if c.Matches(op) && !p.Matches(op) {
				separated = true
				if within {
					t.Fatalf("Within(%v, %v) is unsound at %q", c, p, op)
				}
			}
		}
		if !within && !separated {
			t.Fatalf("not Within(%v, %v), but no operation separates them", c, p)
		}
	})
}

func TestHR045_OperationIntersectIsTheMeet(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genOps(t, "a"), genOps(t, "b")
		ab := a.Intersect(b)
		for _, op := range opProbes(a, b) {
			if got, want := ab.Matches(op), a.Matches(op) && b.Matches(op); got != want {
				t.Fatalf("(%v ∩ %v).Matches(%q) = %v, want %v", a, b, op, got, want)
			}
		}
		if _, ok := ab.Within(a); !ok {
			t.Fatalf("a∩b ⊄ a: %v, %v", ab, a)
		}
	})
}

func genRange(t *rapid.T, label string) Range {
	end := rapid.Custom(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "open") {
			return ""
		}
		return fmt.Sprint(rapid.IntRange(-5, 5).Draw(t, "n"))
	})
	r := Range{Min: end.Draw(t, label+".min"), Max: end.Draw(t, label+".max")}
	if r.Min == "" && r.Max == "" {
		r.Max = "0"
	}
	return r
}

// grid covers every integer end and the points between them.
func grid() []money.Decimal {
	var out []money.Decimal
	for i := -14; i <= 14; i++ {
		out = append(out, money.MustParse(fmt.Sprintf("%d.5", i/2)))
		out = append(out, money.MustParse(fmt.Sprint(i/2)))
	}
	return out
}

func TestHR045_RangeSubsetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genRange(t, "child"), genRange(t, "parent")
		within, separated := c.Within(p), false
		for _, v := range grid() {
			if c.Contains(v) && !p.Contains(v) {
				separated = true
			}
		}
		if within == separated {
			t.Fatalf("Within(%v, %v) = %v, but separated = %v", c, p, within, separated)
		}
		a := c.Intersect(p)
		for _, v := range grid() {
			if a.Contains(v) != (c.Contains(v) && p.Contains(v)) {
				t.Fatalf("(%v ∩ %v).Contains(%s) is wrong", c, p, v)
			}
		}
	})
}

func genAmounts(t *rapid.T, label string) Amounts {
	a := Amounts{}
	for _, c := range []string{"USD", "EUR"} {
		if rapid.Bool().Draw(t, label+"."+c) {
			a[c] = fmt.Sprint(rapid.IntRange(0, 5).Draw(t, label+"."+c+".max"))
		}
	}
	return a
}

func TestHR045_AmountsSubsetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genAmounts(t, "child"), genAmounts(t, "parent")
		_, within := c.Within(p)
		separated := false
		meet := c.Intersect(p)
		for _, cur := range []string{"USD", "EUR", "GBP"} {
			for i := 0; i <= 12; i++ {
				m := money.Money{Amount: money.MustParse(fmt.Sprintf("%d.%d", i/2, (i%2)*5)), Currency: money.Currency(cur)}
				if c.Contains(m) && !p.Contains(m) {
					separated = true
				}
				if meet.Contains(m) != (c.Contains(m) && p.Contains(m)) {
					t.Fatalf("(%v ∩ %v).Contains(%s) is wrong", c, p, m)
				}
			}
		}
		if within == separated {
			t.Fatalf("Within(%v, %v) = %v, but separated = %v", c, p, within, separated)
		}
	})
}

func genWeekly(t *rapid.T, label string) Weekly {
	return Weekly(rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Window {
		from := rapid.IntRange(0, 23).Draw(t, "from")
		to := rapid.IntRange(from+1, 24).Draw(t, "to")
		return Window{Day: rapid.SampledFrom([]string{"mon", "tue"}).Draw(t, "day"), From: hhmm(from * 60), To: hhmm(to * 60)}
	}), 0, 3).Draw(t, label))
}

func TestHR045_WeeklySubsetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genWeekly(t, "child"), genWeekly(t, "parent")
		_, within := c.Within(p)
		meet := c.Intersect(p)
		separated := false
		for m := 0; m < 3*minutesPerDay; m += 30 {
			if c.Contains(m) && !p.Contains(m) {
				separated = true
			}
			if meet.Contains(m) != (c.Contains(m) && p.Contains(m)) {
				t.Fatalf("(%v ∩ %v).Contains(%d) is wrong", c, p, m)
			}
		}
		if within == separated {
			t.Fatalf("Within(%v, %v) = %v, but separated = %v", c, p, within, separated)
		}
	})
}

// genBounds draws a bounds document where each dimension is open or not.
func genBounds(t *rapid.T, label string) Bounds {
	var b Bounds
	maybe := func(name string) bool { return rapid.Bool().Draw(t, label+"."+name) }
	if maybe("ops") {
		o := genOps(t, label+".ops")
		b.Operations = &o
	}
	if maybe("access") {
		b.Access = &Match{IDs: rapid.SliceOfN(rapid.SampledFrom([]string{"read", "write"}), 0, 2).Draw(t, label+".access.ids")}
	}
	if maybe("targets") {
		tg := map[string]Match{}
		for _, typ := range []string{"t.a", "t.b"} {
			if maybe("targets." + typ) {
				tg[typ] = genMatch(t, label+".targets."+typ)
			}
		}
		b.Targets = &tg
	}
	if maybe("accounts") {
		m := genMatch(t, label+".accounts")
		b.Accounts = &m
	}
	if maybe("destinations") {
		m := genMatch(t, label+".destinations")
		b.Destinations = &m
	}
	if maybe("params") {
		ps := map[string]ParamBound{}
		if maybe("n") {
			r := genRange(t, label+".n")
			ps["n"] = ParamBound{Range: &r}
		}
		if maybe("m") {
			ps["m"] = ParamBound{Max: genAmounts(t, label+".m")}
		}
		if maybe("e") {
			m := genMatch(t, label+".e")
			ps["e"] = ParamBound{Values: &m}
		}
		b.Params = map[string]map[string]ParamBound{"a.b": ps}
	}
	if maybe("weekly") {
		w := genWeekly(t, label+".weekly")
		b.Weekly = &w
	}
	return b
}

var monday = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func genAction(t *rapid.T) Action {
	a := Action{
		Operation:       rapid.SampledFrom([]string{"a.b", "a.a", "b.a.b"}).Draw(t, "op"),
		Access:          rapid.SampledFrom([]defs.Access{defs.AccessRead, defs.AccessWrite}).Draw(t, "access"),
		TargetType:      rapid.SampledFrom([]string{"t.a", "t.b", "t.c"}).Draw(t, "ttype"),
		TargetID:        genWord(t, "tid"),
		AccountDeclared: rapid.Bool().Draw(t, "hasacct"),
		Destinations:    rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return genWord(t, "dst") }), 0, 2).Draw(t, "dsts"),
		Params:          defs.Values{},
		Time:            monday.Add(time.Duration(rapid.IntRange(0, 2*minutesPerDay).Draw(t, "minute")) * time.Minute),
	}
	if a.AccountDeclared && rapid.Bool().Draw(t, "acct") {
		a.Account = genWord(t, "account")
	}
	if rapid.Bool().Draw(t, "n") {
		a.Params["n"] = defs.Value{Type: defs.TypeInteger, Int: int64(rapid.IntRange(-6, 6).Draw(t, "n.v"))}
	}
	if rapid.Bool().Draw(t, "m") {
		cur := rapid.SampledFrom([]string{"USD", "EUR", "GBP"}).Draw(t, "m.cur")
		a.Params["m"] = defs.Value{Type: defs.TypeMoney, Money: money.Money{
			Amount: money.MustParse(fmt.Sprint(rapid.IntRange(0, 6).Draw(t, "m.v"))), Currency: money.Currency(cur),
		}}
	}
	if rapid.Bool().Draw(t, "e") {
		a.Params["e"] = defs.Value{Type: defs.TypeIdentifier, Str: genWord(t, "e.v")}
	}
	return a
}

// TestHR045_ChildWithinParentNeverAllowsMore is the property delegation
// relies on: a child that passes the subset test allows no action its
// parent refuses, whatever the action.
func TestHR045_ChildWithinParentNeverAllowsMore(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c, p := genBounds(t, "child"), genBounds(t, "parent")
		if rapid.Bool().Draw(t, "inherit") {
			c = c.Inherit(p)
		}
		if rapid.Bool().Draw(t, "narrow") {
			c = p.Intersect(c).Inherit(p) // usually within; the other branch tests the strictness
		}
		if c.Within(p) != nil {
			return
		}
		for range 8 {
			a := genAction(t)
			if c.Check(a).Outcome == Allowed && p.Check(a).Outcome != Allowed {
				t.Fatalf("child allows %+v but parent refuses it: %+v", a, p.Check(a))
			}
		}
	})
}

// TestHR045_IntersectAllowsExactlyWhatBothAllow backs effective authority:
// the intersection of two levels allows an action exactly when both do.
func TestHR045_IntersectAllowsExactlyWhatBothAllow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genBounds(t, "a"), genBounds(t, "b")
		ab := a.Intersect(b)
		if v := ab.Within(a.Inherit(b)); v != nil {
			t.Fatalf("a∩b is not within a: %v", v)
		}
		for range 8 {
			act := genAction(t)
			got := ab.Check(act).Outcome == Allowed
			want := a.Check(act).Outcome == Allowed && b.Check(act).Outcome == Allowed
			if got != want {
				t.Fatalf("intersection allows=%v, both allow=%v for %+v (a: %+v, b: %+v)", got, want, act, a.Check(act), b.Check(act))
			}
		}
	})
}

// TestHR045_InheritedChildIsWithinParent: a child that only narrows the
// dimensions it sets is within its parent once it inherits the rest.
func TestHR045_InheritedChildIsWithinParent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := genBounds(t, "parent")
		c := p.Intersect(genBounds(t, "narrowing"))
		if v := c.Inherit(p).Within(p); v != nil {
			t.Fatalf("p ∩ x inheriting p is not within p: %v", v)
		}
	})
}
