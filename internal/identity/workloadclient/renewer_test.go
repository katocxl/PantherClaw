// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// fakeServer issues tokens on a fake clock. Its answers are scripted: an
// error in the script is returned once, in order; when the script is empty
// it issues a token valid for life (by its own clock, skew ahead of ours).
type fakeServer struct {
	clk    *clock.Fake
	life   time.Duration
	skew   time.Duration
	script []error
	issued int
}

func (f *fakeServer) issue(context.Context) (workloadclient.Issued, error) {
	if len(f.script) > 0 {
		err := f.script[0]
		f.script = f.script[1:]
		if err != nil {
			return workloadclient.Issued{}, err
		}
	}
	f.issued++
	return workloadclient.Issued{
		Token: fmt.Sprintf("wt-%d", f.issued), ExpiresAt: f.clk.Now().Add(f.skew + f.life), Level: 1,
	}, nil
}

// harness runs a Renewer on the fake clock: every sleep advances it, and
// the run ends after maxSleeps sleeps.
type harness struct {
	clk       *clock.Fake
	r         *workloadclient.Renewer
	sleeps    []time.Duration
	delivered []string
	// deliveredAt and expiresAt are when each token arrived and expires.
	deliveredAt, expiresAt []time.Time
	reports                []string
}

func newHarness(t *testing.T, srv *fakeServer, maxSleeps int, rnd float64) (*harness, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	h := &harness{clk: srv.clk}
	h.r = &workloadclient.Renewer{
		Issue: srv.issue,
		Deliver: func(iss workloadclient.Issued) error {
			h.delivered = append(h.delivered, iss.Token)
			h.deliveredAt = append(h.deliveredAt, h.clk.Now())
			h.expiresAt = append(h.expiresAt, iss.ExpiresAt.Add(-srv.skew))
			return nil
		},
		Report: func(s string) { h.reports = append(h.reports, s) },
		Clock:  srv.clk,
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.sleeps = append(h.sleeps, d)
			h.clk.Advance(d)
			if len(h.sleeps) >= maxSleeps {
				cancel()
			}
			return ctx.Err()
		},
		Rand: func() float64 { return rnd },
	}
	return h, ctx
}

func refusal(code pap.Code) error {
	return connect.NewError(connect.CodeUnauthenticated, "PAP/1: "+string(code))
}

func repeat(d time.Duration, n int) []time.Duration { return slices.Repeat([]time.Duration{d}, n) }

// TestRenewerRenewsHalfwayThroughEachToken: a 10-minute token is renewed
// after 5 minutes, so the process always holds a valid token across many
// lifetimes; jitter only ever makes renewal earlier, by at most 10%.
func TestRenewerRenewsHalfwayThroughEachToken(t *testing.T) {
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	srv := &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute}
	h, ctx := newHarness(t, srv, 12, 0)
	if err := h.r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.sleeps, repeat(5*time.Minute, 12)) {
		t.Fatalf("sleeps = %v", h.sleeps)
	}
	// 12 sleeps of 5 minutes span six token lifetimes; each new token
	// arrived while the one before was still valid.
	if len(h.delivered) != 12 {
		t.Fatalf("delivered %d tokens", len(h.delivered))
	}
	for i := 1; i < len(h.delivered); i++ {
		if !h.deliveredAt[i].Before(h.expiresAt[i-1]) {
			t.Fatalf("token %d arrived at %v, after token %d expired at %v", i, h.deliveredAt[i], i-1, h.expiresAt[i-1])
		}
	}
	if len(h.reports) != 0 {
		t.Fatalf("reports without failures: %q", h.reports)
	}

	srv = &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute}
	h, ctx = newHarness(t, srv, 3, 0.999999)
	if err := h.r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, d := range h.sleeps {
		if d < 4*time.Minute+30*time.Second || d >= 5*time.Minute {
			t.Fatalf("jittered sleep %v outside [4m30s, 5m)", d)
		}
	}
}

// TestRenewerFollowsTheTokensLifetime: an L2 token cut short by its
// attestation (HR-143) is renewed sooner; an expiry beyond 10 minutes (a
// server clock running ahead) is capped at the PAP-1 maximum.
func TestRenewerFollowsTheTokensLifetime(t *testing.T) {
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		life, skew time.Duration
		want       time.Duration
	}{
		{"short L2 token", 2 * time.Minute, 0, time.Minute},
		{"server clock ahead", 10 * time.Minute, 7 * time.Minute, 5 * time.Minute},
		{"server clock behind", 10 * time.Minute, -2 * time.Minute, 4 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := &fakeServer{clk: clock.NewFake(start), life: c.life, skew: c.skew}
			h, ctx := newHarness(t, srv, 3, 0)
			if err := h.r.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(h.sleeps, repeat(c.want, 3)) {
				t.Fatalf("sleeps = %v, want %v", h.sleeps, c.want)
			}
		})
	}
}

// TestRenewerBacksOffAndKeepsTheCurrentToken: transient failures are
// retried after 1 s doubling up to 30 s; nothing replaces the current
// token meanwhile, and each failure says when the token expires, or that
// it has expired.
func TestRenewerBacksOffAndKeepsTheCurrentToken(t *testing.T) {
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	unavailable := connect.NewError(connect.CodeUnavailable, "server restarting")
	srv := &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute}
	srv.script = []error{nil}
	for range 20 {
		srv.script = append(srv.script, unavailable)
	}
	h, ctx := newHarness(t, srv, 22, 0)
	if err := h.r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := append([]time.Duration{5 * time.Minute, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second},
		repeat(30*time.Second, 15)...)
	want = append(want, 5*time.Minute)
	if !slices.Equal(h.sleeps, want) {
		t.Fatalf("sleeps = %v\nwant     %v", h.sleeps, want)
	}
	if !slices.Equal(h.delivered, []string{"wt-1", "wt-2"}) || len(h.reports) != 20 {
		t.Fatalf("delivered %v, %d reports", h.delivered, len(h.reports))
	}
	if r := h.reports[0]; !strings.Contains(r, "server restarting") || !strings.Contains(r, "retrying in 1s") ||
		!strings.Contains(r, "the current token expires at 2026-10-10T09:10:00Z") {
		t.Fatalf("first report %q", r)
	}
	if r := h.reports[19]; !strings.Contains(r, "the current token expired at 2026-10-10T09:10:00Z") {
		t.Fatalf("last report %q", r)
	}

	// Jitter shortens a backoff by at most half.
	srv = &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute, script: []error{unavailable, unavailable}}
	h, ctx = newHarness(t, srv, 2, 0.999999)
	if err := h.r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if h.sleeps[0] <= 500*time.Millisecond || h.sleeps[1] <= time.Second || !strings.Contains(h.reports[0], "there is no token yet") {
		t.Fatalf("jittered backoff %v, reports %q", h.sleeps, h.reports)
	}
}

// TestRenewerStopsAtARefusal: an instance that is not admitted (revoked,
// rejected, or its agent suspended or retired), a key that is not the
// instance's, and an unknown instance end renewal with their code; other
// PAP/1 errors and transport failures are retried.
func TestRenewerStopsAtARefusal(t *testing.T) {
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	for _, code := range []pap.Code{pap.CodeInstanceNotAdmitted, pap.CodeKeyMismatch, pap.CodeInvalidToken} {
		t.Run(string(code), func(t *testing.T) {
			srv := &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute, script: []error{nil, refusal(code)}}
			h, ctx := newHarness(t, srv, 10, 0)
			err := h.r.Run(ctx)
			var r *workloadclient.RefusalError
			if !errors.As(err, &r) || r.Code != code || !strings.Contains(err.Error(), string(code)) {
				t.Fatalf("Run = %v", err)
			}
			if len(h.sleeps) != 1 || len(h.delivered) != 1 || len(h.reports) != 0 {
				t.Fatalf("sleeps %v, delivered %v, reports %q", h.sleeps, h.delivered, h.reports)
			}
		})
	}
	retried := []error{
		refusal(pap.CodeUseNonce), refusal(pap.CodeProofReplay), refusal(pap.CodeInvalidProof), refusal(pap.CodeAttestationLow),
		refusal("rate_limited"), connect.NewError(connect.CodeUnauthenticated, "no PAP code"),
		connect.NewError(connect.CodeInternal, "PAP/1: instance_not_admitted"), errors.New("dial tcp: connection refused"),
	}
	for _, e := range retried {
		srv := &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute, script: []error{e}}
		h, ctx := newHarness(t, srv, 2, 0)
		if err := h.r.Run(ctx); err != nil || len(h.delivered) != 1 || len(h.reports) != 1 {
			t.Fatalf("%v: Run = %v, delivered %v", e, err, h.delivered)
		}
	}
	if _, ok := workloadclient.CodeOf(errors.New("PAP/1: key_mismatch")); ok {
		t.Fatal("a plain error carries no PAP code")
	}
}

// TestRenewerShutsDownCleanly: canceling the context while it waits ends
// Run with nil and no further request; a token that cannot be delivered
// ends it with that error; Renew alone (the first token) reports a refusal.
func TestRenewerShutsDownCleanly(t *testing.T) {
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	srv := &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute}
	h, ctx := newHarness(t, srv, 1, 0)
	if err := h.r.Run(ctx); err != nil || srv.issued != 1 {
		t.Fatalf("Run = %v after %d tokens", err, srv.issued)
	}

	full := errors.New("no space left on device")
	h, ctx = newHarness(t, srv, 5, 0)
	h.r.Deliver = func(workloadclient.Issued) error { return full }
	if err := h.r.Run(ctx); !errors.Is(err, full) {
		t.Fatalf("Run with a failing delivery = %v", err)
	}

	srv = &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute, script: []error{refusal(pap.CodeInstanceNotAdmitted)}}
	h, ctx = newHarness(t, srv, 5, 0)
	var r *workloadclient.RefusalError
	if err := h.r.Renew(ctx); !errors.As(err, &r) {
		t.Fatalf("Renew = %v", err)
	}

	// A token already expired on arrival is a failure, retried.
	srv = &fakeServer{clk: clock.NewFake(start), life: 10 * time.Minute, skew: -11 * time.Minute}
	h, ctx = newHarness(t, srv, 1, 0)
	if err := h.r.Run(ctx); err != nil || len(h.delivered) != 0 || !strings.Contains(h.reports[0], "clock") {
		t.Fatalf("expired token: %v, delivered %v, reports %q", err, h.delivered, h.reports)
	}
}

// TestTokenFileIsReplacedAtomically: the file is created owner-only, each
// token replaces the last whole, no temporary file is left, a symlink at
// the path is replaced rather than written through, and removal is quiet
// when the file is already gone.
func TestTokenFileIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	for _, tok := range []string{"wt-1", "wt-2"} {
		if err := workloadclient.WriteTokenFile(path, tok); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != tok+"\n" {
			t.Fatalf("token file = %q, %v", b, err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v, want 0600", fi.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the token file", len(entries))
	}

	victim, link := filepath.Join(dir, "victim"), filepath.Join(dir, "link")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err == nil {
		if err := workloadclient.WriteTokenFile(link, "wt-3"); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatalf("written through the symlink: %q", b)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("the symlink was not replaced (%v)", err)
		}
	} else {
		t.Logf("no symlinks here (%v); skipping that part", err)
	}

	if err := workloadclient.RemoveTokenFile(path); err != nil {
		t.Fatal(err)
	}
	if err := workloadclient.RemoveTokenFile(path); err != nil {
		t.Fatalf("removing a missing file: %v", err)
	}
	if err := workloadclient.WriteTokenFile(filepath.Join(dir, "missing", "token"), "wt"); err == nil {
		t.Fatal("wrote into a missing directory")
	}
}
