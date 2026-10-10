// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan_test

import (
	"encoding/json/v2"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// jetBrainsFixture lays out JetBrains AI Assistant configurations in the
// formats of the plugin's persisted-state classes: the IDE-level
// llm.mcpServers.xml of four IDEs and versions in each layout (2025.1 and
// 2025.2 entries in the component, the <commands> and <urls> lists 2026.2
// migrates from, 2025.3 state-only entries), ~/.ai/mcp/mcp.json, and a
// project's .ai/mcp/mcp.json (a server map without "mcpServers"),
// .idea/workspace.xml and Rider workspace.xml. It holds credentials in
// environment values and headers, and a run configuration whose environment
// is not an MCP server's.
func jetBrainsFixture(t *testing.T) scan.Options {
	t.Helper()
	root := t.TempDir()
	home, cfg, proj := filepath.Join(root, "home"), filepath.Join(root, "config"), filepath.Join(root, "proj")
	ides := filepath.Join(cfg, "JetBrains")
	// Not credentials: built here so secret scanners skip them; the tests
	// look for "SECRET" in the findings.
	fake := func(tag string) string { return tag + "SECRET" + strings.Repeat("0", 8) }
	write(t, filepath.Join(ides, "PyCharm2025.1", "options", "llm.mcpServers.xml"), `<application>
  <component name="McpApplicationServerCommands" modifiable="true">
    <McpServerCommand sourceId="UserConfigurationSource">
      <option name="allowedToolsNames" />
      <option name="enabled" value="true" />
      <option name="name" value="jb-github" />
      <option name="programPath" value="/usr/local/bin/npx" />
      <option name="arguments" value="-y server-github --token ghp_`+fake("ARG")+`" />
      <option name="workingDirectory" value="" />
      <envs>
        <env name="GITHUB_TOKEN" value="ghp_`+fake("ENV")+`" />
        <env name="LOG_LEVEL" value="debug" />
      </envs>
    </McpServerCommand>
    <McpServerCommand sourceId="UserConfigurationSource">
      <option name="enabled" value="true" />
      <option name="name" value="" />
      <option name="programPath" value="" />
      <option name="arguments" value="" />
      <envs />
    </McpServerCommand>
  </component>
</application>`)
	// 2025.2 still keeps the entries in the component, and has no remote
	// servers.
	write(t, filepath.Join(ides, "GoLand2025.2", "options", "llm.mcpServers.xml"), `<application>
  <component name="McpApplicationServerCommands" modifiable="true">
    <McpServerCommand sourceId="UserConfigurationSource">
      <option name="allowedToolsNames" />
      <option name="enabled" value="true" />
      <option name="name" value="jb-github" />
      <option name="programPath" value="npx" />
      <option name="arguments" value="" />
      <option name="workingDirectory" value="" />
      <envs><env name="GITHUB_TOKEN" value="${env:GITHUB_TOKEN}" /><env name="LOG_LEVEL" value="info" /></envs>
    </McpServerCommand>
  </component>
</application>`)
	// The full definitions in <commands> and <urls> that 2026.2 moves to
	// mcp.json: XmlSerializer's form of McpServerCommand and McpServerURL.
	write(t, filepath.Join(ides, "IntelliJIdea2025.3", "options", "llm.mcpServers.xml"), `<application>
  <component name="McpApplicationServerCommands" modifiable="true" autoEnableExternalChanges="false">
    <commands>
      <McpServerCommand sourceId="UserConfigurationSource">
        <option name="allowedToolsNames">
          <list><option value="query" /></list>
        </option>
        <option name="enabled" value="false" />
        <option name="name" value="jb-db" />
        <option name="programPath" value="uvx" />
        <option name="arguments" value="mcp-server-postgres postgres://admin:PWSECRET@db/app" />
        <option name="workingDirectory" value="" />
        <envs>
          <env name="ANTHROPIC_API_KEY" value="${env:ANTHROPIC_API_KEY}" />
          <env name="PANTHERCLAW_API_KEY" value="pck_live_`+fake("CMD")+`" />
        </envs>
      </McpServerCommand>
    </commands>
    <urls>
      <McpServerURL sourceId="UserConfigurationSource">
        <option name="allowedToolsNames" />
        <option name="enabled" value="true" />
        <option name="name" value="jb-remote" />
        <option name="url" value="https://jb.example.com/mcp?key=QUERYSECRET" />
        <option name="headers">
          <map>
            <entry key="Authorization" value="Bearer ghp_`+fake("HEADER")+`" />
            <entry key="X-Trace" value="on" />
          </map>
        </option>
      </McpServerURL>
    </urls>
  </component>
</application>`)
	write(t, filepath.Join(ides, "WebStorm2025.3", "options", "llm.mcpServers.xml"), `<application>
  <component name="McpApplicationServerCommands" modifiable="true" autoEnableExternalChanges="false">
    <commands>
      <McpServerConfigurationProperties>
        <option name="allowedToolsNames" />
        <option name="enabled" value="true" />
        <option name="name" value="jb-user" />
        <option name="source" value="USER" />
        <option name="userOverride" value="false" />
      </McpServerConfigurationProperties>
    </commands>
    <urls />
  </component>
</application>`)
	write(t, filepath.Join(ides, "consentOptions", "accepted"), "rsch.send.usage.stat:1.1:0")
	write(t, filepath.Join(ides, "port"), "63342")
	write(t, filepath.Join(home, ".ai", "mcp", "mcp.json"), `{"mcpServers": {
		"jb-user": {"command": "npx", "args": ["-y", "server-x"], "env": {"OPENAI_API_KEY": "sk-proj-`+fake("JSON")+`"}},
		"jb-figma": {"type": "http", "url": "http://127.0.0.1:3845/mcp"}}}`)
	write(t, filepath.Join(proj, ".ai", "mcp", "mcp.json"), `{"jb-proj": {"command": "uvx", "args": ["jcodemunch-mcp"],
		"env": {"GITHUB_TOKEN": "ghp_`+fake("BARE")+`"}}}`)
	write(t, filepath.Join(proj, ".idea", "workspace.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="RunManager">
    <configuration name="app" type="Application">
      <option name="name" value="run-config" />
      <option name="programPath" value="/bin/app" />
      <envs><env name="AWS_ACCESS_KEY_ID" value="AKIA`+fake("RUN")+`" /></envs>
    </configuration>
  </component>
  <component name="McpProjectServerCommands">
    <McpServerCommand sourceId="UserConfigurationSource">
      <option name="allowedToolsNames" />
      <option name="enabled" value="true" />
      <option name="name" value="nx-mcp" />
      <option name="programPath" value="npx.cmd" />
      <option name="arguments" value="-y nx-mcp@latest C:/work/shop" />
      <option name="workingDirectory" value="" />
      <envs />
    </McpServerCommand>
  </component>
</project>`)
	write(t, filepath.Join(proj, ".idea", ".idea.Shop", ".idea", "workspace.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="McpProjectServerCommands">
    <commands>
      <McpServerCommand>
        <option name="name" value="rider-proj" />
        <option name="programPath" value="dotnet" />
      </McpServerCommand>
    </commands>
    <urls />
  </component>
</project>`)
	return scan.Options{Host: "laptop-4", Home: home, ConfigDir: cfg, Paths: []string{proj}}
}

// TestF015_ScanReadsJetBrainsAIAssistant (PN-001.1): the scan finds the MCP
// servers of JetBrains AI Assistant in every IDE and version, in each XML
// layout and in .ai/mcp/mcp.json, user and project scope, and the
// credentials in their environment values and headers. A state-only entry
// and a run configuration are not servers.
func TestF015_ScanReadsJetBrainsAIAssistant(t *testing.T) {
	servers := map[string][]map[string]string{}
	creds := map[string]map[string]string{}
	for _, f := range scan.Run(jetBrainsFixture(t)) {
		switch f.Kind {
		case scan.KindMCPServer:
			servers[f.Attributes["name"]] = append(servers[f.Attributes["name"]], f.Attributes)
		case scan.KindEnvSecret:
			creds[f.Attributes["where"]+" "+f.Attributes["name"]] = f.Attributes
		}
	}
	want := map[string]map[string]string{
		"jb-github":  {"transport": "stdio", "command": "npx", "env_names": "GITHUB_TOKEN,LOG_LEVEL"},
		"jb-db":      {"transport": "stdio", "command": "uvx", "env_names": "ANTHROPIC_API_KEY,PANTHERCLAW_API_KEY"},
		"jb-remote":  {"transport": "http", "url_host": "jb.example.com", "header_names": "Authorization,X-Trace"},
		"jb-user":    {"transport": "stdio", "command": "npx", "env_names": "OPENAI_API_KEY"},
		"jb-figma":   {"transport": "http", "url_host": "127.0.0.1:3845"},
		"jb-proj":    {"transport": "stdio", "command": "uvx", "env_names": "GITHUB_TOKEN"},
		"nx-mcp":     {"transport": "stdio", "command": "npx.cmd"},
		"rider-proj": {"transport": "stdio", "command": "dotnet"},
	}
	if len(servers) != len(want) {
		t.Errorf("MCP servers %d, want %d: %v", len(servers), len(want), servers)
	}
	for name, attrs := range want {
		count := 1
		if name == "jb-github" {
			count = 2 // PyCharm 2025.1 and GoLand 2025.2
		}
		if len(servers[name]) != count {
			t.Errorf("server %q found %d times, want %d", name, len(servers[name]), count)
		}
		for _, got := range servers[name] {
			if got["client"] != "jetbrains_ai" {
				t.Errorf("server %q: client %q", name, got["client"])
			}
			for k, v := range attrs {
				if got[k] != v {
					t.Errorf("server %q: %s = %q, want %q", name, k, got[k], v)
				}
			}
		}
	}
	for name, in := range map[string]string{
		"jb-user":    filepath.Join("home", ".ai", "mcp", "mcp.json"), // not from WebStorm's state-only entry
		"jb-remote":  filepath.Join("IntelliJIdea2025.3", "options", "llm.mcpServers.xml"),
		"nx-mcp":     filepath.Join("proj", ".idea", "workspace.xml"),
		"rider-proj": filepath.Join(".idea.Shop", ".idea", "workspace.xml"),
		"jb-proj":    filepath.Join("proj", ".ai", "mcp", "mcp.json"),
	} {
		if len(servers[name]) == 1 && !strings.HasSuffix(servers[name][0]["config"], in) {
			t.Errorf("server %q: config %q, want …%s", name, servers[name][0]["config"], in)
		}
	}
	wantCreds := map[string][2]string{ // where name → kind, redacted
		"jetbrains_ai jb-github GITHUB_TOKEN":          {"github_token", "ghp_…"},
		"jetbrains_ai jb-db PANTHERCLAW_API_KEY":       {"pantherclaw_api_key", "pck_…"},
		"jetbrains_ai jb-remote headers Authorization": {"github_token", "Bearer ghp_…"},
		"jetbrains_ai jb-user OPENAI_API_KEY":          {"openai_api_key", "sk-proj-…"},
		"jetbrains_ai jb-proj GITHUB_TOKEN":            {"github_token", "ghp_…"},
	}
	if len(creds) != len(wantCreds) {
		t.Errorf("credentials %v, want %d (placeholders and run configurations are not MCP credentials)", creds, len(wantCreds))
	}
	for at, w := range wantCreds {
		if c := creds[at]; c["secret_kind"] != w[0] || c["redacted"] != w[1] {
			t.Errorf("credential %q: %v, want %v", at, c, w)
		}
	}
}

// TestF015_JetBrainsMcpJsonForms (PN-001.1): AI Assistant reads an mcp.json
// without "mcpServers" as the server map itself, fails a file whose members
// are not all objects, and ignores what is beside "mcpServers"; so does the
// scan.
func TestF015_JetBrainsMcpJsonForms(t *testing.T) {
	for _, tc := range []struct {
		name, json string
		want       []string
	}{
		{"bare map", `{"a": {"command": "npx"}, "b": {"type": "http", "url": "https://mcp.example.com/mcp"}}`, []string{"a", "b"}},
		{"bare map with a value", `{"a": {"command": "npx"}, "version": 1}`, nil},
		{"null servers", `{"mcpServers": null, "a": {"command": "npx"}}`, nil},
		{"wrapped", `{"mcpServers": {"a": {"command": "npx"}}, "b": {"command": "npx"}}`, []string{"a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			write(t, filepath.Join(home, ".ai", "mcp", "mcp.json"), tc.json)
			var names []string
			for _, f := range scan.Run(scan.Options{Host: "h", Home: home}) {
				if f.Kind == scan.KindMCPServer {
					names = append(names, f.Attributes["name"])
				}
			}
			if slices.Sort(names); !slices.Equal(names, tc.want) {
				t.Errorf("servers %v, want %v", names, tc.want)
			}
		})
	}
}

// TestHR056_JetBrainsCredentialsAreRedacted: environment and header values,
// arguments, URL queries and other components' values from the JetBrains
// configurations never appear in a finding.
func TestHR056_JetBrainsCredentialsAreRedacted(t *testing.T) {
	b, err := json.Marshal(scan.Run(jetBrainsFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("a secret leaked into the findings: %s", b)
	}
}

// TestHR100_JetBrainsXMLIsBounded: an XML configuration that is malformed,
// larger than MaxFileSize, nested deeper than MaxNesting, declares an
// entity or another encoding is skipped whole; the other IDEs' files are
// still read.
func TestHR100_JetBrainsXMLIsBounded(t *testing.T) {
	cfg := t.TempDir()
	server := func(name string) string {
		return `<McpServerCommand><option name="name" value="` + name + `" /><option name="programPath" value="npx" />` +
			`<envs><env name="GITHUB_TOKEN" value="ghp_` + name + `SECRET0000" /></envs></McpServerCommand>`
	}
	doc := func(inner string) string {
		return `<application><component name="McpApplicationServerCommands">` + inner + `</component></application>`
	}
	nest := func(n int) string { return strings.Repeat("<x>", n) + strings.Repeat("</x>", n) }
	for ide, content := range map[string]string{
		"Good2025.1":       doc(server("good")),
		"AtLimit2025.1":    doc(server("atlimit") + nest(scan.MaxNesting-2)), // application, component, then 30
		"TooDeep2025.1":    doc(server("toodeep") + nest(scan.MaxNesting-1)),
		"Truncated2025.1":  strings.TrimSuffix(doc(server("truncated")), "</component></application>"),
		"Mismatched2025.1": strings.Replace(doc(server("mismatched")), "</component>", "</commands>", 1),
		"TooBig2025.1":     doc(server("toobig") + "<!--" + strings.Repeat(" ", scan.MaxFileSize) + "-->"),
		"Entity2025.1": `<?xml version="1.0"?><!DOCTYPE application [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>` +
			strings.Replace(doc(server("entity")), "npx", "&xxe;", 1),
		"Latin2025.1":  `<?xml version="1.0" encoding="ISO-8859-1"?>` + doc(server("latin")),
		"Binary2025.1": "\x00\x01\x02" + doc(server("binary")),
	} {
		write(t, filepath.Join(cfg, "JetBrains", ide, "options", "llm.mcpServers.xml"), content)
	}
	var names []string
	for _, f := range scan.Run(scan.Options{Host: "h", ConfigDir: cfg}) {
		if f.Kind == scan.KindMCPServer {
			names = append(names, f.Attributes["name"])
		}
		if f.Kind == scan.KindEnvSecret && !strings.HasPrefix(f.Attributes["where"], "jetbrains_ai good") &&
			!strings.HasPrefix(f.Attributes["where"], "jetbrains_ai atlimit") {
			t.Errorf("a credential from a skipped file: %v", f.Attributes)
		}
	}
	if slices.Sort(names); !slices.Equal(names, []string{"atlimit", "good"}) {
		t.Errorf("servers %v, want only good and atlimit", names)
	}
}
