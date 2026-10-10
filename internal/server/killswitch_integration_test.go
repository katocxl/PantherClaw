// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR113_TheEmergencyStopPageAndContainmentServiceAreServed: the page
// and its script are mounted, its actions need the CSRF proof and a
// session, and ContainmentService (read only) refuses an anonymous caller.
func TestHR113_TheEmergencyStopPageAndContainmentServiceAreServed(t *testing.T) {
	d := dbtest.New(t)
	base := serveM5(t, testConfig(t, d, RoleAll))
	org := ids.New[ids.Org]()
	if code := statusM5(t, http.MethodGet, base+"/containment?org="+org.String()); code != http.StatusSeeOther {
		t.Errorf("/containment = %d, want 303 (sign in)", code)
	}
	if code := statusM5(t, http.MethodGet, base+"/static/containment.js"); code != http.StatusOK {
		t.Errorf("/static/containment.js = %d", code)
	}
	for _, path := range []string{"/containment/kill-switch/engage", "/containment/kill-switch/restore"} {
		if code := statusM5(t, http.MethodPost, base+path); code != http.StatusForbidden {
			t.Errorf("POST %s without the CSRF proof = %d, want 403", path, code)
		}
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	cs := pantherclawv1connect.NewContainmentServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	if _, err := cs.GetKillSwitch(context.Background(), &pantherclawv1.GetKillSwitchRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("ContainmentService anonymous: %v", err)
	}
}
