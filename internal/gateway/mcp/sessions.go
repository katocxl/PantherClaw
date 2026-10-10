// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// MCP 2025-11-25 sessions (G0 M6 design decision 13, HR-083). initialize
// opens a session: a 256-bit random id bound to the gateway's org, the
// connection, the verified instance, the key that signed the request and
// the run. Every later POST must carry the id and PAP/1 credentials of that
// instance and key in that run, and is verified again. A session ends
// after 30 idle minutes, after 8 hours, when its run expires or ends, or on
// DELETE; an instance keeps at most 16, and opening another ends its least
// recently used one. Sessions live in this gateway's memory: a restart
// ends them, and clients initialize again on the 404. Session ids are
// never logged.
const (
	// LegacyVersion is the MCP revision with sessions this face speaks.
	LegacyVersion = "2025-11-25"
	// HeaderSessionID carries the session id (2025-11-25 transport).
	HeaderSessionID = "Mcp-Session-Id"

	sessionIdle            = 30 * time.Minute
	sessionMax             = 8 * time.Hour
	maxSessionsPerInstance = 16
	maxSessions            = 10_000
)

// errSessionsFull: the gateway holds as many sessions as it may.
var errSessionsFull = errors.New("mcp: too many sessions")

// session is what a session id is bound to.
type session struct {
	conn, instance, jkt, run string
	seen, expires            time.Time
}

// binds reports whether a request on conn, whose token names instance and
// key jkt, in run (empty: the session's), belongs to the session. Values
// from the token are unverified here; the Authority verifies them on the
// same request.
func (s session) binds(conn string, in dispatch.Inbound) bool {
	return s.conn == conn && s.instance == in.Instance && s.jkt == in.JKT && (in.Run == "" || in.Run == s.run)
}

type sessions struct {
	now func() time.Time
	mu  sync.Mutex
	// m is keyed by the SHA-256 of the session id.
	m map[[sha256.Size]byte]*session
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{now: now, m: map[[sha256.Size]byte]*session{}}
}

func sessionKey(id string) [sha256.Size]byte { return sha256.Sum256([]byte(id)) }

// open starts a session ending at most 8 hours from now and never after
// runExpires, and returns its id.
func (s *sessions) open(conn, instance, jkt, run string, runExpires time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.m {
		if !v.live(now) {
			delete(s.m, k)
		}
	}
	var mine [][sha256.Size]byte
	for k, v := range s.m {
		if v.instance == instance {
			mine = append(mine, k)
		}
	}
	if len(mine) >= maxSessionsPerInstance {
		oldest := mine[0]
		for _, k := range mine[1:] {
			if s.m[k].seen.Before(s.m[oldest].seen) {
				oldest = k
			}
		}
		delete(s.m, oldest)
	}
	if len(s.m) >= maxSessions {
		return "", errSessionsFull
	}
	expires := now.Add(sessionMax)
	if !runExpires.IsZero() && runExpires.Before(expires) {
		expires = runExpires
	}
	s.m[sessionKey(id)] = &session{conn: conn, instance: instance, jkt: jkt, run: run, seen: now, expires: expires}
	return id, nil
}

func (v *session) live(now time.Time) bool {
	return now.Before(v.expires) && now.Sub(v.seen) < sessionIdle
}

// get returns a live session.
func (s *sessions) get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[sessionKey(id)]
	if !ok || !v.live(s.now()) {
		return session{}, false
	}
	return *v, true
}

// touch records a verified request in the session.
func (s *sessions) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[sessionKey(id)]; ok {
		v.seen = s.now()
	}
}

// end ends a session.
func (s *sessions) end(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sessionKey(id))
}
