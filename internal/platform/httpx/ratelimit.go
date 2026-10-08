// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// Limiter is a fixed-window rate limiter keyed by an arbitrary string
// (client IP, credential id). It bounds its memory: when it tracks more than
// maxKeys keys it starts a fresh window for everyone. It protects the
// unauthenticated authentication endpoints against brute force (SB-2).
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	clock   clock.Clock
	start   time.Time
	counts  map[string]int
}

// NewLimiter allows limit events per key per window.
func NewLimiter(limit int, window time.Duration, clk clock.Clock) *Limiter {
	if clk == nil {
		clk = clock.System{}
	}
	return &Limiter{limit: limit, window: window, maxKeys: 100_000, clock: clk, counts: map[string]int{}}
}

// Allow records an event for key and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if now.Sub(l.start) >= l.window || len(l.counts) >= l.maxKeys {
		l.start, l.counts = now, map[string]int{}
	}
	l.counts[key]++
	return l.counts[key] <= l.limit
}

// ClientIP returns the host of the request's remote address. Forwarding
// headers are not trusted (no proxy is configured as trusted).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
