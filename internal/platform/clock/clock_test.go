// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package clock

import (
	"testing"
	"time"
)

func TestSystemReturnsUTC(t *testing.T) {
	if loc := (System{}).Now().Location(); loc != time.UTC {
		t.Fatalf("System.Now location = %v, want UTC", loc)
	}
}

func TestFake(t *testing.T) {
	start := time.Date(2026, 10, 8, 12, 0, 0, 0, time.FixedZone("BST", 3600))
	f := NewFake(start)
	if got := f.Now(); !got.Equal(start) || got.Location() != time.UTC {
		t.Fatalf("Now = %v, want %v in UTC", got, start)
	}
	f.Advance(5 * time.Second)
	if got, want := f.Now(), start.Add(5*time.Second); !got.Equal(want) {
		t.Fatalf("after Advance: %v, want %v", got, want)
	}
	f.Advance(-time.Hour)
	if got, want := f.Now(), start.Add(5*time.Second); !got.Equal(want) {
		t.Fatalf("negative Advance moved time: %v, want %v", got, want)
	}
	later := start.Add(24 * time.Hour)
	f.Set(later)
	if got := f.Now(); !got.Equal(later) {
		t.Fatalf("after Set: %v, want %v", got, later)
	}
}

func TestFakeImplementsClock(t *testing.T) {
	var _ Clock = NewFake(time.Time{})
	var _ Clock = System{}
}
