// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube

import (
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// tokenRefresh is how long a reviewer token read from token_file is used
// before the file is read again, so a rotated token is picked up without a
// restart (THREAT_MODEL R-15). Kubelet replaces a projected token once 80% of
// its lifetime has passed, at least 2 minutes before it expires, so a minute
// is always in time.
const tokenRefresh = time.Minute

// tokenFile is a cluster's reviewer credential. It keeps the last token it
// read and reads the file again once that copy is tokenRefresh old.
type tokenFile struct {
	path  string
	clock clock.Clock

	mu     sync.Mutex
	token  pclog.Secret[[]byte]
	readAt time.Time
}

// readTokenFile reads path once; a missing or unreadable file stops the
// server from starting.
func readTokenFile(path string, clk clock.Clock) (*tokenFile, error) {
	tok, err := config.ReadSecretFile(path)
	if err != nil {
		return nil, err
	}
	return &tokenFile{path: path, clock: clk, token: tok, readAt: clk.Now()}, nil
}

// get returns the current token. When the file cannot be read again (for
// example while an operator rewrites it), the last token stays in use and
// the next call tries again: the API server decides whether that token
// still works, and refuses the call if not.
func (f *tokenFile) get() pclog.Secret[[]byte] {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock.Now()
	// A wall clock that moved backwards counts as stale too, so a clock
	// step can never pin an old token.
	if age := now.Sub(f.readAt); age >= 0 && age < tokenRefresh {
		return f.token
	}
	if tok, err := config.ReadSecretFile(f.path); err == nil {
		f.token, f.readAt = tok, now
	}
	return f.token
}
