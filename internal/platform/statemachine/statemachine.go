// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package statemachine provides table-driven state machines (ARCHITECTURE
// §6.2). Domain packages declare every allowed transition in one table; any
// transition not in the table is illegal. Persisting a transition is always a
// conditional update (`UPDATE … WHERE state = <from>`, HR-004), which the
// database layer checks with db.ExpectOneRow.
package statemachine

import (
	"errors"
	"fmt"
	"slices"
)

// ErrIllegalTransition reports a transition that is not in the machine's table.
var ErrIllegalTransition = errors.New("statemachine: illegal transition")

// Machine is an immutable table of allowed transitions between states of type S.
type Machine[S comparable] struct {
	name    string
	allowed map[S][]S
	states  []S
}

// New builds a machine from a transition table: each key lists the states it
// may move to. States that appear only as targets are terminal. New panics on
// a self-transition or a duplicate target, because those are programming
// errors in a static table; call it from package-level variable initializers.
func New[S comparable](name string, table map[S][]S) *Machine[S] {
	m := &Machine[S]{name: name, allowed: make(map[S][]S, len(table))}
	seen := map[S]bool{}
	add := func(s S) {
		if !seen[s] {
			seen[s] = true
			m.states = append(m.states, s)
		}
	}
	for from, tos := range table {
		add(from)
		for i, to := range tos {
			if to == from {
				panic(fmt.Sprintf("statemachine %s: self-transition on %v", name, from))
			}
			if slices.Contains(tos[:i], to) {
				panic(fmt.Sprintf("statemachine %s: duplicate transition %v → %v", name, from, to))
			}
			add(to)
		}
		m.allowed[from] = slices.Clone(tos)
	}
	return m
}

// Name returns the machine's name.
func (m *Machine[S]) Name() string { return m.name }

// Can reports whether from → to is allowed.
func (m *Machine[S]) Can(from, to S) bool {
	return slices.Contains(m.allowed[from], to)
}

// Check returns ErrIllegalTransition (wrapped with context) unless from → to
// is allowed.
func (m *Machine[S]) Check(from, to S) error {
	if m.Can(from, to) {
		return nil
	}
	return fmt.Errorf("%w: %s %v → %v", ErrIllegalTransition, m.name, from, to)
}

// Next returns the states reachable from s in one step.
func (m *Machine[S]) Next(s S) []S { return slices.Clone(m.allowed[s]) }

// Terminal reports whether s has no outgoing transitions.
func (m *Machine[S]) Terminal(s S) bool { return len(m.allowed[s]) == 0 }

// States returns every state mentioned in the table.
func (m *Machine[S]) States() []S { return slices.Clone(m.states) }
