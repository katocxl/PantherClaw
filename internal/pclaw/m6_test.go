// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordGateways struct {
	pantherclawv1connect.UnimplementedGatewayAdminServiceHandler
	list   *pantherclawv1.ListGatewaysRequest
	revoke *pantherclawv1.RevokeGatewayRequest
}

func (r *recordGateways) ListGateways(_ context.Context, req *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error) {
	r.list = req
	return &pantherclawv1.ListGatewaysResponse{}, nil
}

func (r *recordGateways) RevokeGateway(_ context.Context, req *pantherclawv1.RevokeGatewayRequest) (*pantherclawv1.RevokeGatewayResponse, error) {
	r.revoke = req
	return &pantherclawv1.RevokeGatewayResponse{}, nil
}

type fixedKillSwitch struct {
	pantherclawv1connect.UnimplementedContainmentServiceHandler
}

func (fixedKillSwitch) GetKillSwitch(context.Context, *pantherclawv1.GetKillSwitchRequest) (*pantherclawv1.GetKillSwitchResponse, error) {
	return &pantherclawv1.GetKillSwitchResponse{
		Engaged: true, Epoch: 7, EngagedBy: "user:0192aaaa-bbbb-7ccc-8ddd-000000000001", EngageTime: timestamppb.Now(),
		PageUrl: "https://pc.example/containment?org=0192aaaa-bbbb-7ccc-8ddd-000000000002",
	}, nil
}

func TestM6Commands(t *testing.T) {
	gw := &recordGateways{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterGatewayAdminServiceHandler(cs, gw)
	pantherclawv1connect.RegisterContainmentServiceHandler(cs, fixedKillSwitch{})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	if code, _, errs := run(t, env, "gateway", "list", "--include-revoked"); code != 0 || !gw.list.GetIncludeRevoked() {
		t.Fatalf("gateway list = %d %q, request %v", code, errs, gw.list)
	}
	if code, _, errs := run(t, env, "gateway", "revoke", "0192aaaa-bbbb-7ccc-8ddd-000000000003", "--reason", "lost host"); code != 0 ||
		gw.revoke.GetReason() != "lost host" {
		t.Fatalf("gateway revoke = %d %q, request %v", code, errs, gw.revoke)
	}
	code, out, errs := run(t, env, "killswitch", "status")
	if code != 0 || !strings.Contains(out, `"engaged": true`) ||
		!strings.Contains(errs, "emergency-stop page: https://pc.example/containment?org=0192aaaa-bbbb-7ccc-8ddd-000000000002") {
		t.Fatalf("killswitch status = %d %q %q", code, out, errs)
	}
	// There is no command that engages or restores.
	for _, verb := range []string{"engage", "restore", "on", "off"} {
		if code, _, _ := run(t, env, "killswitch", verb); code == 0 {
			t.Fatalf("killswitch %s succeeded", verb)
		}
	}
}
