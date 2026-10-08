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

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordTenancy struct {
	pantherclawv1connect.UnimplementedTenancyServiceHandler
	update *pantherclawv1.UpdateTeamRequest
	env    *pantherclawv1.CreateEnvironmentRequest
}

func (r *recordTenancy) UpdateTeam(_ context.Context, req *pantherclawv1.UpdateTeamRequest) (*pantherclawv1.UpdateTeamResponse, error) {
	r.update = req
	return &pantherclawv1.UpdateTeamResponse{Team: &pantherclawv1.Team{Id: req.GetId(), Name: req.GetName()}}, nil
}

func (r *recordTenancy) CreateEnvironment(_ context.Context, req *pantherclawv1.CreateEnvironmentRequest) (*pantherclawv1.CreateEnvironmentResponse, error) {
	r.env = req
	return &pantherclawv1.CreateEnvironmentResponse{Environment: &pantherclawv1.Environment{Slug: req.GetSlug()}}, nil
}

func TestCommandsSendOnlyWhatIsGiven(t *testing.T) {
	rec := &recordTenancy{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterTenancyServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, out, errs := run(t, env, "team", "update", "0192aaaa-bbbb-7ccc-8ddd-000000000001", "--name", "Refunds")
	if code != 0 || rec.update.Name == nil || rec.update.Description != nil || !strings.Contains(out, `"name": "Refunds"`) {
		t.Fatalf("team update = %d %q %q, request %v", code, out, errs, rec.update)
	}
	if code, _, _ := run(t, env, "env", "create", "--slug", "prod", "--name", "Prod", "--kind", "prod"); code != 0 ||
		rec.env.GetKind() != pantherclawv1.EnvironmentKind_ENVIRONMENT_KIND_PRODUCTION {
		t.Fatalf("env create = %d, %v", code, rec.env)
	}
	if code, _, errs := run(t, env, "env", "create", "--slug", "x", "--name", "X", "--kind", "qa"); code != 1 || !strings.Contains(errs, "--kind") {
		t.Fatalf("bad kind = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "team", "update"); code != 2 {
		t.Fatalf("missing id = %d", code)
	}
	if code, _, _ := run(t, env, "team", "get", "id", "extra"); code != 2 {
		t.Fatalf("extra argument = %d", code)
	}
}

func TestEveryCommandUsageStartsWithItsName(t *testing.T) {
	for name, c := range commands {
		if !strings.HasPrefix(c.usage, name) {
			t.Errorf("command %q has usage %q", name, c.usage)
		}
	}
	if len(commands) < 45 {
		t.Fatalf("%d commands", len(commands))
	}
}
