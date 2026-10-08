// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package statemachine

import (
	"errors"
	"testing"
)

type permitState string

const (
	issued      permitState = "ISSUED"
	dispatching permitState = "DISPATCHING"
	dispatched  permitState = "DISPATCHED"
	unknown     permitState = "UNKNOWN"
	released    permitState = "RELEASED"
)

// The permit machine from ARCHITECTURE §6.2, used here as the reference
// example for the HR-004 transition rules.
var permits = New("permit", map[permitState][]permitState{
	issued:      {dispatching, released},
	dispatching: {dispatched, unknown},
})

func TestHR004_OnlyTabledTransitionsAreLegal(t *testing.T) {
	legal := map[[2]permitState]bool{
		{issued, dispatching}:     true,
		{issued, released}:        true,
		{dispatching, dispatched}: true,
		{dispatching, unknown}:    true,
	}
	states := permits.States()
	if len(states) != 5 {
		t.Fatalf("states = %v, want 5", states)
	}
	// Exhaustive: every ordered pair of states is either legal or rejected.
	for _, from := range states {
		for _, to := range states {
			want := legal[[2]permitState{from, to}]
			if got := permits.Can(from, to); got != want {
				t.Errorf("Can(%s → %s) = %v, want %v", from, to, got, want)
			}
			err := permits.Check(from, to)
			if want && err != nil {
				t.Errorf("Check(%s → %s) = %v, want nil", from, to, err)
			}
			if !want && !errors.Is(err, ErrIllegalTransition) {
				t.Errorf("Check(%s → %s) = %v, want ErrIllegalTransition", from, to, err)
			}
		}
	}
}

func TestHR004_ReleasedAndUnknownAreTerminal(t *testing.T) {
	// UNKNOWN must never be auto-released (HR-003): it has no outgoing edge here.
	for _, s := range []permitState{dispatched, unknown, released} {
		if !permits.Terminal(s) {
			t.Errorf("%s should be terminal, next = %v", s, permits.Next(s))
		}
	}
	if permits.Terminal(issued) {
		t.Error("ISSUED must not be terminal")
	}
}

func TestNewRejectsBadTables(t *testing.T) {
	for name, table := range map[string]map[permitState][]permitState{
		"self":      {issued: {issued}},
		"duplicate": {issued: {released, released}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New did not panic", name)
				}
			}()
			New(name, table)
		}()
	}
}

func TestNextIsACopy(t *testing.T) {
	next := permits.Next(issued)
	next[0] = unknown
	if !permits.Can(issued, dispatching) {
		t.Fatal("mutating Next's result changed the machine")
	}
}
