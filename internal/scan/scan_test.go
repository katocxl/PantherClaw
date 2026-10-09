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
	"unicode/utf8"

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

// editorFixture lays out the configurations of Windsurf, Devin Desktop, Zed
// (JSONC with trailing commas, current and older server formats) and Junie,
// with credentials in environment values and HTTP headers, and placeholders
// that are not credentials.
func editorFixture(t *testing.T) scan.Options {
	t.Helper()
	root := t.TempDir()
	home, cfg, proj := filepath.Join(root, "home"), filepath.Join(root, "config"), filepath.Join(root, "proj")
	write(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"mcpServers": {
		"wind-remote": {"serverUrl": "https://wind.example.com/mcp?key=QUERYSECRET", "headers": {"Authorization": "Bearer ghp_HEADERSECRET0000"}},
		"wind-local": {"command": "npx", "args": ["-y", "server-github"], "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}}}}`)
	opaque := "OPAQUESECRET" + strings.Repeat("1", 4) // not a credential: built here so secret scanners skip it
	write(t, filepath.Join(cfg, "devin", "mcp_config.json"), `{"mcpServers": {
		"devin": {"serverUrl": "https://devin.example.com/mcp", "headers": {"X-API-Key": "`+opaque+`"}}}}`)
	write(t, filepath.Join(home, ".config", "zed", "settings.json"), `// Zed settings
{
  "theme": "One Dark",
  "context_servers": {
    "zed-new": {"command": "uvx", "args": ["mcp-server-git"], "env": {},},
    /* before 2025 */
    "zed-old": {"command": {"path": "/usr/bin/node", "args": ["srv.js"], "env": {"ANTHROPIC_API_KEY": "sk-ant-OLDSECRET0000",},}, "settings": {},},
    "zed-remote": {"url": "https://zed.example.com/mcp", "headers": {"Authorization": "Basic BASICSECRET00",},},
    "trailing, ]": {"source": "extension", "settings": {"list": [1, 2,],},},
  },
}`)
	write(t, filepath.Join(proj, ".zed", "settings.json"), `{"context_servers": {"zed-proj": {"command": "python"}}}`)
	write(t, filepath.Join(home, ".junie", "mcp", "mcp.json"), `{"mcpServers": {
		"junie-user": {"url": "https://junie.example.com/v1", "headers": {"Authorization": "Bearer ${env:JUNIE_TOKEN}", "X-Trace": "on-all-requests"}}}}`)
	write(t, filepath.Join(proj, ".junie", "mcp", "mcp.json"), `{"mcpServers": {"junie-proj": {"command": "docker"}}}`)
	return scan.Options{Host: "laptop-2", Home: home, ConfigDir: cfg, Paths: []string{proj}}
}

// TestF015_ScanReadsWindsurfZedAndJunie (PN-001.1): the scan finds the MCP
// servers of Windsurf, Devin Desktop, Zed and Junie, user and project
// scope, and the credentials in their environment values and headers.
func TestF015_ScanReadsWindsurfZedAndJunie(t *testing.T) {
	servers := map[string]map[string]string{}
	creds := map[string]map[string]string{}
	for _, f := range scan.Run(editorFixture(t)) {
		switch f.Kind {
		case scan.KindMCPServer:
			servers[f.Attributes["name"]] = f.Attributes
		case scan.KindEnvSecret:
			creds[f.Attributes["where"]+" "+f.Attributes["name"]] = f.Attributes
		}
	}
	want := map[string]map[string]string{
		"wind-remote": {"client": "windsurf", "transport": "http", "url_host": "wind.example.com", "header_names": "Authorization"},
		"wind-local":  {"client": "windsurf", "transport": "stdio", "command": "npx", "env_names": "GITHUB_TOKEN"},
		"devin":       {"client": "devin_desktop", "transport": "http", "url_host": "devin.example.com", "header_names": "X-API-Key"},
		"zed-new":     {"client": "zed", "transport": "stdio", "command": "uvx"},
		"zed-old":     {"client": "zed", "transport": "stdio", "command": "node", "env_names": "ANTHROPIC_API_KEY"},
		"zed-remote":  {"client": "zed", "transport": "http", "url_host": "zed.example.com", "header_names": "Authorization"},
		"trailing, ]": {"client": "zed", "transport": ""},
		"zed-proj":    {"client": "zed", "transport": "stdio", "command": "python"},
		"junie-user":  {"client": "junie", "transport": "http", "url_host": "junie.example.com", "header_names": "Authorization,X-Trace"},
		"junie-proj":  {"client": "junie", "transport": "stdio", "command": "docker"},
	}
	if len(servers) != len(want) {
		t.Errorf("MCP servers %d, want %d: %v", len(servers), len(want), servers)
	}
	for name, attrs := range want {
		for k, v := range attrs {
			if servers[name][k] != v {
				t.Errorf("server %q: %s = %q, want %q", name, k, servers[name][k], v)
			}
		}
	}
	wantCreds := map[string][2]string{ // where name → kind, redacted
		"windsurf wind-remote headers Authorization": {"github_token", "Bearer ghp_…"},
		"devin_desktop devin headers X-API-Key":      {"http_credential", "…"},
		"zed zed-old ANTHROPIC_API_KEY":              {"anthropic_api_key", "sk-ant-…"},
		"zed zed-remote headers Authorization":       {"http_credential", "Basic …"},
	}
	if len(creds) != len(wantCreds) {
		t.Errorf("credentials %v, want %d (placeholders and plain headers are not credentials)", creds, len(wantCreds))
	}
	for at, w := range wantCreds {
		if c := creds[at]; c["secret_kind"] != w[0] || c["redacted"] != w[1] {
			t.Errorf("credential %q: %v, want %v", at, c, w)
		}
	}
}

// TestHR056_EditorConfigCredentialsAreRedacted: header values, URL queries
// and environment values from the editors' configurations never appear in
// a finding.
func TestHR056_EditorConfigCredentialsAreRedacted(t *testing.T) {
	b, err := json.Marshal(scan.Run(editorFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("a secret leaked into the findings: %s", b)
	}
}

// TestF015_AConfigNamedTwiceIsReadOnce: when two locations name one file,
// as on a case-insensitive file system, its servers are reported once.
func TestF015_AConfigNamedTwiceIsReadOnce(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".config", "zed", "settings.json"), `{"context_servers": {"git": {"command": "uvx"}}}`)
	upper := filepath.Join(home, ".CONFIG")
	if _, err := os.Stat(filepath.Join(upper, "zed", "settings.json")); err != nil {
		t.Skip("case-sensitive file system")
	}
	got := scan.Run(scan.Options{Host: "h", Home: home, ConfigDir: upper})
	if len(got) != 1 {
		t.Fatalf("findings %v, want the one server once", got)
	}
}

// TestF015_LongAttributesStayValidUTF8: clipping never splits a character,
// so a submission is never refused for invalid UTF-8.
func TestF015_LongAttributesStayValidUTF8(t *testing.T) {
	dir := t.TempDir()
	name := "a" + strings.Repeat("ü", 200) // 401 bytes: a 256-byte cut lands inside a character
	write(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers": {"`+name+`": {"command": "python"}}}`)
	got := scan.Run(scan.Options{Host: "h", Paths: []string{dir}})
	if len(got) != 1 {
		t.Fatalf("findings %v", got)
	}
	for k, v := range got[0].Attributes {
		if !utf8.ValidString(v) || len(v) > 256 {
			t.Errorf("attribute %s: %d bytes, valid UTF-8 %v", k, len(v), utf8.ValidString(v))
		}
	}
}
