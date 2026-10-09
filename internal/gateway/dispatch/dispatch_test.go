// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

const testOrg = "01920000-0000-7000-8000-0000000000a1"

// TestHR091_GatewayNonceCacheExpires: a cached nonce is served at most
// nonceCacheFor and never past the expiry the Authority gave.
func TestHR091_GatewayNonceCacheExpires(t *testing.T) {
	var n nonces
	n.set("n-1", time.Time{})
	if n.get() != "n-1" {
		t.Fatal("fresh nonce not served")
	}
	n.set("n-2", time.Now().Add(-time.Second))
	if n.get() != "" {
		t.Fatal("served a nonce past its expiry")
	}
	n.mu.Lock()
	n.cur, n.until = "n-3", time.Now().Add(-time.Millisecond)
	n.mu.Unlock()
	if n.get() != "" {
		t.Fatal("served a nonce past the cache lifetime")
	}
}

// TestF642_OutcomeClassification: what reached the target decides the
// outcome; a refused dial, the egress guard and a request for another host
// sent nothing, so they are FAILED; anything after sending is UNKNOWN.
func TestF642_OutcomeClassification(t *testing.T) {
	dial := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	read := &net.OpError{Op: "read", Err: errors.New("connection reset")}
	for _, tc := range []struct {
		status  int
		err     error
		outcome pb.Outcome
		class   Class
		code    string
	}{
		{http.StatusCreated, nil, pb.Outcome_OUTCOME_ACCEPTED, "", ""},
		{http.StatusConflict, nil, pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused},
		{http.StatusBadGateway, nil, pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain},
		{http.StatusFound, nil, pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain},
		{0, dial, pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetUnreachable},
		{0, &net.OpError{Op: "dial", Err: httpx.ErrDestinationDenied}, pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeEgressDenied},
		{0, egress.ErrHost, pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeRequest},
		{0, read, pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain},
		{0, errors.New("timeout awaiting response headers"), pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain},
	} {
		o, class, code := classify(tc.status, tc.err)
		if o != tc.outcome || class != tc.class || code != tc.code {
			t.Errorf("%d %v: %v %q %q", tc.status, tc.err, o, class, code)
		}
	}
}
