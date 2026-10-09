// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan_test

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/scan"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture lays out a home, a config dir and a project with MCP configs,
// agent frameworks and credentials.
func fixture(t *testing.T) scan.Options {
	t.Helper()
	root := t.TempDir()
	home, cfg, proj := filepath.Join(root, "home"), filepath.Join(root, "config"), filepath.Join(root, "proj")
	write(t, filepath.Join(cfg, "Claude", "claude_desktop_config.json"), `{"mcpServers": {"github": {
		"command": "/usr/local/bin/npx", "args": ["-y", "server-github", "--token", "ghp_ARGSECRET0000"],
		"env": {"GITHUB_TOKEN": "ghp_ENVSECRET00000"}}}}`)
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"remote": {"url": "https://mcp.example.com/sse?token=QUERYSECRET"}},
		"projects": {"/work": {"mcpServers": {"db": {"command": "uvx"}}}}}`)
	write(t, filepath.Join(cfg, "Code", "User", "settings.json"), "// user settings\n{\n  /* MCP */ \"mcp\": {\"servers\": {\"fs\": {\"command\": \"node\"}}},\n  \"url\": \"http://x//y\"\n}")
	write(t, filepath.Join(proj, ".mcp.json"), `{"mcpServers": {"tickets": {"command": "python"}}}`)
	write(t, filepath.Join(proj, "package.json"), `{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0", "langchain": "0.3.0", "react": "19"}}`)
	write(t, filepath.Join(proj, "svc", "requirements.txt"), "crewai==0.5\nrequests\n")
	write(t, filepath.Join(proj, "node_modules", "dep", "package.json"), `{"dependencies": {"langchain": "1"}}`)
	fake := "ENVSECRET" + strings.Repeat("0", 12) // not a credential: the test looks for it in the findings
	return scan.Options{
		Host: "laptop-1", Home: home, ConfigDir: cfg, Paths: []string{proj},
		Environ: []string{"PANTHERCLAW_API_KEY=pck_live_" + fake, "PATH=/bin", "OPENAI_API_KEY=sk-proj-" + fake, "SHORT=x"},
	}
}

// TestF015_ScanFindsMCPConfigsAgentProjectsAndCredentials (PN-001.1).
func TestF015_ScanFindsMCPConfigsAgentProjectsAndCredentials(t *testing.T) {
	o := fixture(t)
	got := scan.Run(o)
	count := map[string]int{}
	names := map[string]bool{}
	for _, f := range got {
		count[f.Kind]++
		names[f.Attributes["name"]] = true
		if len(f.Key) != 64 {
			t.Errorf("key %q", f.Key)
		}
	}
	if count[scan.KindMCPServer] != 5 || !names["github"] || !names["remote"] || !names["db"] || !names["fs"] || !names["tickets"] {
		t.Errorf("MCP servers %d: %v", count[scan.KindMCPServer], names)
	}
	if count[scan.KindAgentProject] != 2 {
		t.Errorf("agent projects %d (node_modules must be skipped)", count[scan.KindAgentProject])
	}
	if count[scan.KindEnvSecret] != 3 {
		t.Errorf("credentials %d, want the env GitHub token and two environment keys", count[scan.KindEnvSecret])
	}
	for _, f := range got {
		if f.Kind == scan.KindAgentProject && strings.HasSuffix(f.Attributes["path"], "proj") &&
			f.Attributes["frameworks"] != "langchain,mcp-sdk" {
			t.Errorf("frameworks %q", f.Attributes["frameworks"])
		}
	}
	again := scan.Run(o)
	if !slices.EqualFunc(got, again, func(a, b scan.Finding) bool { return a.Key == b.Key }) {
		t.Error("finding keys are not stable across scans")
	}
}

// TestHR056_ScanFindingsCarryNoSecrets: values, arguments and URL queries
// never appear in a finding; a credential shows only its known prefix.
func TestHR056_ScanFindingsCarryNoSecrets(t *testing.T) {
	got := scan.Run(fixture(t))
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("a secret leaked into the findings: %s", b)
	}
	for _, f := range got {
		if f.Kind == scan.KindEnvSecret && f.Attributes["name"] == "PANTHERCLAW_API_KEY" &&
			(f.Attributes["redacted"] != "pck_…" || f.Attributes["secret_kind"] != "pantherclaw_api_key") {
			t.Errorf("pck_ key finding %v", f.Attributes)
		}
	}
}
