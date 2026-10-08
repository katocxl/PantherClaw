// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package clock provides the injectable time source used by PantherClaw.
//
// Application code never calls time.Now directly: it receives a Clock so that
// tests are deterministic. Deadlines that guard security decisions (permit
// expiry, approval expiry) use the database clock inside a transaction
// instead (BUILD_GUIDE §3.1).
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	// Now returns the current time in UTC.
	Now() time.Time
}

// System is the wall clock.
type System struct{}

// Now returns the current wall-clock time in UTC.
func (System) Now() time.Time { return time.Now().UTC() }

// Fake is a manually controlled clock for tests. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake clock set to t (converted to UTC).
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

// Now returns the fake current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward by d. Negative durations are ignored
// so that time never runs backwards.
func (f *Fake) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the fake clock to t (converted to UTC).
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}
