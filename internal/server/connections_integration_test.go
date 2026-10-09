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
)

// TestIntConnectionServiceIsServed: ConnectionService is on the public API
// and refuses an anonymous caller.
func TestIntConnectionServiceIsServed(t *testing.T) {
	d := dbtest.New(t)
	base := serveM5(t, testConfig(t, d, RoleAll))
	hc := &http.Client{Timeout: 5 * time.Second}
	cs := pantherclawv1connect.NewConnectionServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	if _, err := cs.ListConnections(context.Background(), &pantherclawv1.ListConnectionsRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("ConnectionService anonymous: %v", err)
	}
}
