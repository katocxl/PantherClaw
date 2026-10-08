// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// Limiter is a fixed-window rate limiter keyed by an arbitrary string
// (client IP, credential id). It bounds its memory: when it tracks more than
// maxKeys keys it starts a fresh window for everyone. It protects the
// unauthenticated authentication endpoints against brute force (SB-2).
type Limiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	maxKeys  int
	clock    clock.Clock
	start    time.Time
	counts   map[string]int
	clientIP ClientIPFunc
}

// NewLimiter allows limit events per key per window. Requests are keyed by
// ClientIP until WithClientIP sets another resolver.
func NewLimiter(limit int, window time.Duration, clk clock.Clock) *Limiter {
	if clk == nil {
		clk = clock.System{}
	}
	return &Limiter{limit: limit, window: window, maxKeys: 100_000, clock: clk, counts: map[string]int{}, clientIP: ClientIP}
}

// WithClientIP sets how request keys are derived (TrustedProxyClientIP
// behind a reverse proxy) and returns the limiter.
func (l *Limiter) WithClientIP(f ClientIPFunc) *Limiter {
	if f != nil {
		l.clientIP = f
	}
	return l
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

// AllowRequest records an event for the request's client address.
func (l *Limiter) AllowRequest(r *http.Request) bool { return l.Allow(l.ClientIP(r)) }

// ClientIP returns the request's client address as the limiter sees it.
func (l *Limiter) ClientIP(r *http.Request) string { return l.clientIP(r) }

// ClientIPFunc returns the client address of a request.
type ClientIPFunc func(*http.Request) string

// ClientIP returns the host of the request's remote address. Forwarding
// headers are not trusted.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// TrustedProxyClientIP returns a ClientIPFunc for a server behind reverse
// proxies. For a request whose peer is one of the trusted proxies, the
// client is the right-most X-Forwarded-For address that is not itself a
// trusted proxy (each proxy appends the address it received from); for any
// other peer, forwarding headers are ignored and the peer address is used.
// A malformed header falls back to the peer address, so a client can never
// choose its own key.
func TrustedProxyClientIP(trusted []netip.Prefix) ClientIPFunc {
	trusted = slices.Clone(trusted)
	isTrusted := func(a netip.Addr) bool {
		a = a.Unmap()
		return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	return func(r *http.Request) string {
		peer := ClientIP(r)
		pa, err := netip.ParseAddr(peer)
		if err != nil || !isTrusted(pa) {
			return peer
		}
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return peer
			}
			if !isTrusted(a) {
				return a.Unmap().String()
			}
		}
		return peer
	}
}
