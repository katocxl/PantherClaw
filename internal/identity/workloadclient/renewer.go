// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

const (
	// MaxLifetime is the longest a workload token lives (PAP-1 §3.4). A
	// later expiry in a response is not believed: it would only mean the
	// server's clock runs ahead of ours.
	MaxLifetime = 10 * time.Minute
	// minBackoff and maxBackoff bound the wait after a failed renewal.
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Issued is one workload token as the server returned it.
type Issued struct {
	Token string
	// ExpiresAt is the token's expiry by the server's clock.
	ExpiresAt time.Time
	// Level is the attestation level (1 or 2).
	Level int
}

// RefusalError is a renewal the server refused for good: the instance is
// not admitted (revoked, rejected, never admitted, or its agent is
// suspended or retired), the key is not the instance's, or the server does
// not know the instance. Asking again cannot change the answer.
type RefusalError struct {
	Code pap.Code
	Err  error
}

func (e *RefusalError) Error() string { return "renewal refused: " + string(e.Code) }

func (e *RefusalError) Unwrap() error { return e.Err }

// final are the refusals that end renewal. Everything else, invalid_proof
// included (a clock more than a minute off causes it), is retried.
var final = map[pap.Code]bool{
	pap.CodeInstanceNotAdmitted: true,
	pap.CodeKeyMismatch:         true,
	pap.CodeInvalidToken:        true,
}

// CodeOf returns the PAP-Error code of a refusal from a PantherClaw
// server, which sends it as the message of an Unauthenticated error.
func CodeOf(err error) (pap.Code, bool) {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		return "", false
	}
	c, ok := strings.CutPrefix(ce.Message(), "PAP/1: ")
	return pap.Code(c), ok && c != ""
}

// Renewer keeps a workload token fresh for a long-running process: it asks
// for a new token once half of the current one's lifetime has passed,
// retries failures with backoff while the current token stays in place, and
// stops at a refusal (PAP-1 §3.4: each renewal is a fresh key-only proof).
// It never logs a token.
type Renewer struct {
	// Issue asks the server for a token.
	Issue func(context.Context) (Issued, error)
	// Deliver hands a new token over (a file, or memory). An error ends Run:
	// a token that cannot be handed over helps nobody.
	Deliver func(Issued) error
	// Report receives one line for each failure; nil discards them.
	Report func(string)
	// Clock is the local clock (clock.System when nil).
	Clock clock.Clock
	// Sleep waits d or until ctx ends (a timer when nil).
	Sleep func(ctx context.Context, d time.Duration) error
	// Rand returns a number in [0, 1) for jitter (crypto/rand when nil).
	Rand func() float64

	have             bool
	renewAt, expires time.Time
}

// Renew asks for one token and delivers it. It returns a *RefusalError
// when the server refused for good.
func (r *Renewer) Renew(ctx context.Context) error {
	iss, err := r.Issue(ctx)
	if err != nil {
		if code, ok := CodeOf(err); ok && final[code] {
			return &RefusalError{Code: code, Err: err}
		}
		return err
	}
	now := r.now()
	life := min(iss.ExpiresAt.Sub(now), MaxLifetime)
	if life <= 0 {
		return errors.New("the server sent a token that has already expired (check this machine's clock)")
	}
	if err := r.Deliver(iss); err != nil {
		return &deliveryError{err}
	}
	half := life / 2
	r.have, r.expires = true, now.Add(life)
	r.renewAt = now.Add(half - time.Duration(float64(half)*0.1*r.rand()))
	return nil
}

// Run renews until ctx ends (it then returns nil), the server refuses (a
// *RefusalError), or a token cannot be delivered. Without a current token
// it asks at once.
func (r *Renewer) Run(ctx context.Context) error {
	var wait time.Duration
	if r.have {
		wait = r.renewAt.Sub(r.now())
	}
	for failures := 0; ; {
		if wait > 0 {
			_ = r.sleep(ctx, wait) // a stop shows in ctx
		}
		if stopped(ctx) {
			return nil
		}
		err := r.Renew(ctx)
		var refusal *RefusalError
		var delivery *deliveryError
		switch {
		case stopped(ctx):
			return nil // a request cut short by a stop is not a failure
		case err == nil:
			failures, wait = 0, r.renewAt.Sub(r.now())
			continue
		case errors.As(err, &refusal):
			return refusal
		case errors.As(err, &delivery):
			return delivery.err
		}
		failures++
		wait = r.backoff(failures)
		r.report(fmt.Sprintf("renewal failed: %v; retrying in %s; %s", err, wait.Round(time.Millisecond), r.current()))
	}
}

// current describes the token in place, for failure reports.
func (r *Renewer) current() string {
	switch {
	case !r.have:
		return "there is no token yet"
	case r.now().Before(r.expires):
		return "the current token expires at " + r.expires.Format(time.RFC3339)
	default:
		return "the current token expired at " + r.expires.Format(time.RFC3339)
	}
}

// backoff is the wait after the n-th consecutive failure: 1 s doubling up
// to 30 s, less up to half of it at random.
func (r *Renewer) backoff(n int) time.Duration {
	d := maxBackoff
	if n <= 5 {
		d = min(minBackoff<<(n-1), maxBackoff)
	}
	return d - time.Duration(float64(d)/2*r.rand())
}

func stopped(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (r *Renewer) now() time.Time {
	if r.Clock == nil {
		return time.Now()
	}
	return r.Clock.Now()
}

func (r *Renewer) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *Renewer) rand() float64 {
	if r.Rand != nil {
		return r.Rand()
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}

func (r *Renewer) report(s string) {
	if r.Report != nil {
		r.Report(s)
	}
}

// deliveryError is a token that could not be handed over.
type deliveryError struct{ err error }

func (e *deliveryError) Error() string { return e.err.Error() }

func (e *deliveryError) Unwrap() error { return e.err }
