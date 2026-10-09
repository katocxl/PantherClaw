// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// TestHR010_TheGatewayDispatchesNothingWithoutFreshContainment: a stale
// containment view, a revoked gateway and the kill switch each stop a
// request before the Authority is asked; nothing reaches the target.
func TestHR010_TheGatewayDispatchesNothingWithoutFreshContainment(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
	}{
		"stale":       {control.ErrStale, http.StatusServiceUnavailable},
		"revoked":     {control.ErrRevoked, http.StatusServiceUnavailable},
		"kill switch": {control.ErrKillSwitch, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, "", func(h *harness) { h.containment.err = tc.err })
			code, r, _ := h.post(t, inbound, nil)
			if code != tc.code || r.Error != tc.err.Error() || h.auth.snap().authorize != 0 || h.target.calls() != 0 {
				t.Fatalf("%d %+v, authorize %d, target %d", code, r, h.auth.snap().authorize, h.target.calls())
			}
		})
	}
}

// TestHR010_ContainmentChangingDuringTheDecisionStopsDispatch: when the
// view goes stale or the epoch moves past the permit's while the Authority
// decides, BeginDispatch is never called and nothing is sent.
func TestHR010_ContainmentChangingDuringTheDecisionStopsDispatch(t *testing.T) {
	for name, after := range map[string]func(*fakeContainment){
		"epoch moved":  func(f *fakeContainment) { f.epoch = 2 },
		"stream stale": func(f *fakeContainment) { f.err = control.ErrStale },
		"kill switch":  func(f *fakeContainment) { f.err = control.ErrKillSwitch },
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, "", func(h *harness) { h.containment.after = after })
			code, _, _ := h.post(t, inbound, nil)
			if s := h.auth.snap(); code == http.StatusOK || s.authorize != 1 || s.begins != 0 || h.target.calls() != 0 {
				t.Fatalf("%d, authorize %d, begins %d, target %d", code, s.authorize, s.begins, h.target.calls())
			}
		})
	}
}

// TestHR010_ServingWaitsForTheFirstSnapshot: WaitReady blocks until the
// containment view has its first snapshot, and gives up after its timeout.
func TestHR010_ServingWaitsForTheFirstSnapshot(t *testing.T) {
	h := setup(t, "")
	pending := &fakeContainment{ready: make(chan struct{})}
	h.gw.containment = pending
	if err := h.gw.WaitReady(context.Background(), 50*time.Millisecond); err == nil {
		t.Fatal("ready without a snapshot")
	}
	close(pending.ready)
	if err := h.gw.WaitReady(context.Background(), time.Second); err != nil {
		t.Fatalf("not ready after the snapshot: %v", err)
	}
}
