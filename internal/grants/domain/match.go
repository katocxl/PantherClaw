// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// maxEntries caps every list in a bounds document (T-023).
const maxEntries = 256

// Match is an allowlist of exact values and byte prefixes. A value matches
// when it equals one of IDs or starts with one of Prefixes. Prefixes compare
// bytes: write "refs/heads/feature/" rather than "refs/heads/feature" when
// the separator matters. A Match with no entries matches nothing.
//
// Match is a lattice: Within decides "narrower or equal" exactly, and
// Intersect is the greatest lower bound (HR-045).
type Match struct {
	IDs      []string `json:"ids,omitzero"`
	Prefixes []string `json:"prefixes,omitzero"`
}

// Matches reports whether v is allowed.
func (m Match) Matches(v string) bool {
	return slices.Contains(m.IDs, v) || slices.ContainsFunc(m.Prefixes, func(p string) bool { return strings.HasPrefix(v, p) })
}

// Within reports whether every value m allows is allowed by p. When it is
// not, it returns an entry of m that p does not cover. The test is exact: an
// exact id is covered when p matches it; a prefix only by a prefix of it,
// because no finite set of ids or longer prefixes covers every extension of
// a prefix and the prefix itself.
func (m Match) Within(p Match) (string, bool) {
	for _, id := range m.IDs {
		if !p.Matches(id) {
			return id, false
		}
	}
	for _, q := range m.Prefixes {
		if !slices.ContainsFunc(p.Prefixes, func(pp string) bool { return strings.HasPrefix(q, pp) }) {
			return q + "*", false
		}
	}
	return "", true
}

// Intersect returns the values both allow. Two prefixes that match a common
// value are comparable (one starts with the other), so the meet of two
// prefixes is the longer one or nothing.
func (m Match) Intersect(o Match) Match {
	var out Match
	for _, id := range m.IDs {
		if o.Matches(id) {
			out.IDs = append(out.IDs, id)
		}
	}
	for _, id := range o.IDs {
		if m.Matches(id) {
			out.IDs = append(out.IDs, id)
		}
	}
	for _, a := range m.Prefixes {
		for _, b := range o.Prefixes {
			switch {
			case strings.HasPrefix(a, b):
				out.Prefixes = append(out.Prefixes, a)
			case strings.HasPrefix(b, a):
				out.Prefixes = append(out.Prefixes, b)
			}
		}
	}
	return out.normalize()
}

// normalize sorts and deduplicates, drops prefixes covered by a shorter
// prefix and ids covered by a prefix. It never changes what m matches.
func (m Match) normalize() Match {
	pre := slices.Clone(m.Prefixes)
	slices.Sort(pre)
	pre = slices.Compact(pre)
	var keep []string
	for _, p := range pre { // sorted: a covering prefix comes first
		if !slices.ContainsFunc(keep, func(k string) bool { return strings.HasPrefix(p, k) }) {
			keep = append(keep, p)
		}
	}
	idList := slices.Clone(m.IDs)
	slices.Sort(idList)
	idList = slices.Compact(idList)
	idList = slices.DeleteFunc(idList, func(id string) bool {
		return slices.ContainsFunc(keep, func(k string) bool { return strings.HasPrefix(id, k) })
	})
	return Match{IDs: nonNil(idList), Prefixes: nonNil(keep)}
}

// nonNil keeps "present but empty" distinct from "absent" after slicing.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (m Match) validate(name string, prefixes bool) error {
	if len(m.IDs)+len(m.Prefixes) > maxEntries {
		return invalid("%s: at most %d entries", name, maxEntries)
	}
	if !prefixes && len(m.Prefixes) > 0 {
		return invalid("%s: prefixes are not allowed here", name)
	}
	for _, v := range append(slices.Clone(m.IDs), m.Prefixes...) {
		if err := actionir.CheckIdentifier(name, v); err != nil {
			return invalid("%s: %q is not a valid identifier (HR-102)", name, v)
		}
	}
	return nil
}

// String renders m for explanations.
func (m Match) String() string {
	parts := slices.Clone(m.IDs)
	for _, p := range m.Prefixes {
		parts = append(parts, p+"*")
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// Ops is a set of operation patterns: exact names such as
// payments.refund.create, or prefixes such as payments.* that match every
// operation under them. It is a lattice like Match.
type Ops []string

var opPrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,6}\.\*$`)

// prefix returns the "x." part of an "x.*" pattern.
func opPrefix(p string) (string, bool) {
	if s, ok := strings.CutSuffix(p, "*"); ok {
		return s, true
	}
	return "", false
}

func opMatches(p, op string) bool {
	if pre, ok := opPrefix(p); ok {
		return strings.HasPrefix(op, pre)
	}
	return p == op
}

// opCovers reports whether pattern p matches everything q matches.
func opCovers(p, q string) bool {
	pre, ok := opPrefix(p)
	if !ok {
		return p == q
	}
	if qpre, qok := opPrefix(q); qok {
		return strings.HasPrefix(qpre, pre)
	}
	return strings.HasPrefix(q, pre)
}

// Matches reports whether op is allowed.
func (o Ops) Matches(op string) bool {
	return slices.ContainsFunc(o, func(p string) bool { return opMatches(p, op) })
}

// Within reports whether o allows nothing p refuses, or returns a pattern
// of o that p does not cover. Operation names are unbounded, so a prefix
// pattern is covered only by a single pattern, never by a union.
func (o Ops) Within(p Ops) (string, bool) {
	for _, q := range o {
		if !slices.ContainsFunc(p, func(pp string) bool { return opCovers(pp, q) }) {
			return q, false
		}
	}
	return "", true
}

// Intersect returns the operations both allow. Two patterns that match a
// common operation are comparable, so the meet is pairwise.
func (o Ops) Intersect(p Ops) Ops {
	out := Ops{}
	for _, a := range o {
		for _, b := range p {
			switch {
			case opCovers(a, b):
				out = append(out, b)
			case opCovers(b, a):
				out = append(out, a)
			}
		}
	}
	return out.normalize()
}

func (o Ops) normalize() Ops {
	s := slices.Clone(o)
	slices.Sort(s)
	s = slices.Compact(s)
	out := Ops{}
	for _, p := range s {
		covered := slices.ContainsFunc(s, func(q string) bool { return q != p && opCovers(q, p) })
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

func (o Ops) validate(name string) error {
	if len(o) > maxEntries {
		return invalid("%s: at most %d entries", name, maxEntries)
	}
	for _, p := range o {
		if !actionir.ValidOperation(p) && !opPrefixPattern.MatchString(p) {
			return invalid("%s: %q is neither an operation nor a prefix such as payments.*", name, p)
		}
	}
	return nil
}
