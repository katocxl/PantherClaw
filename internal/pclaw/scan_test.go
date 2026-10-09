// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordScan struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	req *pantherclawv1.SubmitScanFindingsRequest
}

func (r *recordScan) SubmitScanFindings(_ context.Context, req *pantherclawv1.SubmitScanFindingsRequest) (*pantherclawv1.SubmitScanFindingsResponse, error) {
	r.req = req
	return &pantherclawv1.SubmitScanFindingsResponse{Created: int32(len(req.GetFindings()))}, nil
}

// TestF015_ScanStaysLocalUnlessSubmitted: the scan prints its findings;
// --submit sends MCP servers and agent projects, never credentials.
func TestF015_ScanStaysLocalUnlessSubmitted(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		".mcp.json":    `{"mcpServers": {"tickets": {"command": "python", "env": {"OPENAI_API_KEY": "sk-proj-LEAKCHECK0000"}}}}`,
		"package.json": `{"dependencies": {"@openai/agents": "1"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &recordScan{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env")
	if code != 0 || !strings.Contains(out, "MCP servers: 1") || !strings.Contains(out, "openai-agents") ||
		!strings.Contains(out, "Credentials (redacted): 1") || strings.Contains(out, "LEAKCHECK") || rec.req != nil {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	code, out, errs = run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit")
	if code != 0 || !strings.Contains(out, "2 new discovered agents") || len(rec.req.GetFindings()) != 2 {
		t.Fatalf("scan --submit = %d %q %q, request %v", code, out, errs, rec.req)
	}
	for _, f := range rec.req.GetFindings() {
		if f.GetKind() == "env_secret" || f.GetAttributes()["host"] != "" {
			t.Errorf("submitted %v", f)
		}
	}
}
