// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordM3 struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	pantherclawv1connect.UnimplementedIdentityServiceHandler
	pantherclawv1connect.UnimplementedRunServiceHandler
	create  *pantherclawv1.CreateAgentRequest
	list    *pantherclawv1.ListAgentsRequest
	propose *pantherclawv1.ProposeIssuerEntryRequest
	admit   *pantherclawv1.AdmitInstanceRequest
	start   *pantherclawv1.StartRunRequest
}

func (r *recordM3) CreateAgent(_ context.Context, req *pantherclawv1.CreateAgentRequest) (*pantherclawv1.CreateAgentResponse, error) {
	r.create = req
	return &pantherclawv1.CreateAgentResponse{}, nil
}

func (r *recordM3) ListAgents(_ context.Context, req *pantherclawv1.ListAgentsRequest) (*pantherclawv1.ListAgentsResponse, error) {
	r.list = req
	return &pantherclawv1.ListAgentsResponse{}, nil
}

func (r *recordM3) ProposeIssuerEntry(_ context.Context, req *pantherclawv1.ProposeIssuerEntryRequest) (*pantherclawv1.ProposeIssuerEntryResponse, error) {
	r.propose = req
	return &pantherclawv1.ProposeIssuerEntryResponse{}, nil
}

func (r *recordM3) AdmitInstance(_ context.Context, req *pantherclawv1.AdmitInstanceRequest) (*pantherclawv1.AdmitInstanceResponse, error) {
	r.admit = req
	return &pantherclawv1.AdmitInstanceResponse{}, nil
}

func (r *recordM3) StartRun(_ context.Context, req *pantherclawv1.StartRunRequest) (*pantherclawv1.StartRunResponse, error) {
	r.start = req
	return &pantherclawv1.StartRunResponse{}, nil
}

// TestM3CommandsBuildTheRequests: flags map onto the M3 requests; enums
// are parsed and nothing is sent for invalid values.
func TestM3CommandsBuildTheRequests(t *testing.T) {
	rec := &recordM3{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	pantherclawv1connect.RegisterIdentityServiceHandler(cs, rec)
	pantherclawv1connect.RegisterRunServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const id = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

	if code, _, errs := run(t, env, "agent", "create", "--name", "coder", "--team", id, "--env", id, "--owner", id, "--context", "ci"); code != 0 ||
		rec.create.GetExecutionContext() != pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI || rec.create.BackupOwnerUserId != nil {
		t.Fatalf("agent create = %d %q, %v", code, errs, rec.create)
	}
	if code, _, _ := run(t, env, "agent", "create", "--name", "x", "--context", "laptop"); code != 1 {
		t.Errorf("unknown context accepted: %d", code)
	}
	if code, _, _ := run(t, env, "agent", "list", "--state", "claimed,verified"); code != 0 ||
		!slices.Equal(rec.list.GetStates(), []pantherclawv1.AgentState{pantherclawv1.AgentState_AGENT_STATE_CLAIMED, pantherclawv1.AgentState_AGENT_STATE_VERIFIED}) {
		t.Fatalf("agent list states %v", rec.list.GetStates())
	}
	if code, _, errs := run(t, env, "issuer", "propose-github", "--agent", id, "--repository-id", "1", "--owner-id", "2",
		"--workflow-ref", "o/r/.github/workflows/a.yml@refs/heads/main", "--workflow-ref", "o/r/.github/workflows/a.yml@refs/tags/v1",
		"--auto-admit", "--reason", "ci"); code != 0 || len(rec.propose.GetGithub().GetWorkflowRefs()) != 2 || !rec.propose.GetAutoAdmit() ||
		rec.propose.GetGithub().GetJobType() != pantherclawv1.GithubJobType_GITHUB_JOB_TYPE_WORKFLOW {
		t.Fatalf("issuer propose-github = %d %q, %v", code, errs, rec.propose)
	}
	if code, _, _ := run(t, env, "instance", "admit", id, "--fingerprint", "fp"); code != 0 || rec.admit.GetFingerprint() != "fp" {
		t.Fatalf("instance admit %v", rec.admit)
	}
	subject := filepath.Join(t.TempDir(), "subject")
	if err := os.WriteFile(subject, []byte("eyJ.subject.token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "run", "start", id, "--task", "refund", "--subject-token-file", subject, "--subject-token-type", "access_token"); code != 0 ||
		rec.start.GetSubjectToken() != "eyJ.subject.token" || rec.start.GetTaskRef() != "refund" ||
		rec.start.GetSubjectTokenType() != pantherclawv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_ACCESS_TOKEN {
		t.Fatalf("run start = %d %q, %v", code, errs, rec.start)
	}
}
