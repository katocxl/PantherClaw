// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package scan is the local shadow-agent scan behind `pclaw scan`
// (PN-001.1, F015). It reads, and never changes, the MCP configurations of
// Claude Desktop, Claude Code, Cursor and VS Code, looks for agent-framework
// projects under the given directories, and checks the environment for
// credentials agents use, PantherClaw pck_ keys included. Secrets never
// appear in a finding: only the variable name, the kind of credential and
// its well-known prefix. Findings stay on the machine unless submitted.
package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Finding kinds.
const (
	KindMCPServer    = "mcp_server"
	KindAgentProject = "agent_project"
	KindEnvSecret    = "env_secret"
)

// Limits keep a scan bounded on large trees.
const (
	MaxDepth    = 5
	MaxFiles    = 20000
	MaxFileSize = 1 << 20
	maxValue    = 256
)

// Finding is one thing the scan found. Attributes are what a person needs to
// recognize it; they never hold a secret.
type Finding struct {
	Kind       string            `json:"kind"`
	Key        string            `json:"key"` // stable per machine: hex SHA-256
	Attributes map[string]string `json:"attributes"`
}

// Options say where to look.
type Options struct {
	// Host names the machine in finding keys and attributes.
	Host string
	// Home and ConfigDir locate the per-user configurations
	// (os.UserHomeDir, os.UserConfigDir).
	Home, ConfigDir string
	// Paths are project directories to walk (at most MaxDepth deep).
	Paths []string
	// Environ is the environment to check (os.Environ).
	Environ []string
}

func key(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func clip(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= maxValue {
		return s
	}
	return s[:maxValue]
}

// Run scans and returns the findings, sorted by kind and key.
func Run(o Options) []Finding {
	var out []Finding
	for _, c := range clientConfigs(o) {
		out = append(out, mcpFindings(o.Host, c.client, c.path, c.servers)...)
	}
	for _, p := range o.Paths {
		out = append(out, projects(o, p)...)
	}
	out = append(out, envSecrets(o.Host, "environment", o.Environ)...)
	slices.SortFunc(out, func(a, b Finding) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Key == b.Key })
}

// clientConfig is one MCP configuration file and the path to its servers.
type clientConfig struct {
	client, path string
	servers      []string // JSON member path to the servers object
}

func clientConfigs(o Options) []clientConfig {
	var out []clientConfig
	add := func(client, path string, servers ...string) {
		if path != "" {
			out = append(out, clientConfig{client: client, path: path, servers: servers})
		}
	}
	if o.ConfigDir != "" {
		add("claude_desktop", filepath.Join(o.ConfigDir, "Claude", "claude_desktop_config.json"), "mcpServers")
		add("vscode", filepath.Join(o.ConfigDir, "Code", "User", "mcp.json"), "servers")
		add("vscode", filepath.Join(o.ConfigDir, "Code", "User", "settings.json"), "mcp", "servers")
	}
	if o.Home != "" {
		add("claude_desktop", filepath.Join(o.Home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "mcpServers")
		add("claude_code", filepath.Join(o.Home, ".claude.json"), "mcpServers")
		add("cursor", filepath.Join(o.Home, ".cursor", "mcp.json"), "mcpServers")
	}
	for _, p := range o.Paths {
		add("project", filepath.Join(p, ".mcp.json"), "mcpServers")
		add("cursor", filepath.Join(p, ".cursor", "mcp.json"), "mcpServers")
		add("vscode", filepath.Join(p, ".vscode", "mcp.json"), "servers")
	}
	return out
}

// readJSON reads a JSON or JSONC file into an object; anything else is
// skipped.
func readJSON(path string) map[string]any {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileSize {
		return nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: scanning the user's own configuration
	if err != nil {
		return nil
	}
	var v map[string]any
	if json.Unmarshal(stripComments(b), &v, jsontext.AllowDuplicateNames(true)) != nil {
		return nil
	}
	return v
}

// stripComments removes // and /* */ comments outside strings (JSONC).
func stripComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return out
}

func member(v map[string]any, path []string) map[string]any {
	for _, p := range path {
		next, ok := v[p].(map[string]any)
		if !ok {
			return nil
		}
		v = next
	}
	return v
}

func mcpFindings(host, client, path string, serversAt []string) []Finding {
	doc := readJSON(path)
	if doc == nil {
		return nil
	}
	groups := []map[string]any{member(doc, serversAt)}
	if client == "claude_code" {
		// ~/.claude.json also keeps per-project servers.
		if projects, ok := doc["projects"].(map[string]any); ok {
			for _, p := range projects {
				if pm, ok := p.(map[string]any); ok {
					groups = append(groups, member(pm, serversAt))
				}
			}
		}
	}
	var out []Finding
	for _, servers := range groups {
		for name, raw := range servers {
			s, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			attrs := map[string]string{"client": client, "config": clip(path), "name": clip(name), "host": clip(host)}
			if cmd, ok := s["command"].(string); ok && cmd != "" {
				attrs["transport"], attrs["command"] = "stdio", clip(filepath.Base(cmd))
			}
			if u, ok := s["url"].(string); ok && u != "" {
				attrs["transport"] = "http"
				if pu, err := url.Parse(u); err == nil {
					attrs["url_host"] = clip(pu.Host) // never the path or query: tokens live there
				}
			}
			var envNames []string
			if env, ok := s["env"].(map[string]any); ok {
				for k, v := range env {
					envNames = append(envNames, k)
					if val, ok := v.(string); ok {
						out = append(out, envSecrets(host, client+" "+name, []string{k + "=" + val})...)
					}
				}
			}
			slices.Sort(envNames)
			if len(envNames) > 0 {
				attrs["env_names"] = clip(strings.Join(envNames, ","))
			}
			out = append(out, Finding{Kind: KindMCPServer, Key: key(KindMCPServer, host, path, name), Attributes: attrs})
		}
	}
	return out
}

// frameworks maps a dependency name to the framework it indicates.
var frameworks = map[string]string{
	"langchain": "langchain", "langchain-core": "langchain", "@langchain/core": "langchain", "langchain-community": "langchain",
	"langgraph": "langgraph", "@langchain/langgraph": "langgraph", "crewai": "crewai", "autogen-agentchat": "autogen",
	"pyautogen": "autogen", "openai-agents": "openai-agents", "@openai/agents": "openai-agents", "llama-index": "llamaindex",
	"llamaindex": "llamaindex", "pydantic-ai": "pydantic-ai", "semantic-kernel": "semantic-kernel", "mastra": "mastra",
	"@mastra/core": "mastra", "claude-agent-sdk": "claude-agent-sdk", "@anthropic-ai/claude-agent-sdk": "claude-agent-sdk",
	"mcp": "mcp-sdk", "@modelcontextprotocol/sdk": "mcp-sdk", "github.com/modelcontextprotocol/go-sdk": "mcp-sdk",
	"github.com/mark3labs/mcp-go": "mcp-sdk", "github.com/tmc/langchaingo": "langchain",
}

var skipDirs = []string{".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target"}

// projects walks dir for dependency manifests that use an agent framework.
func projects(o Options, dir string) []Finding {
	var out []Finding
	files := 0
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			if slices.Contains(skipDirs, d.Name()) || strings.Count(rel, string(filepath.Separator)) >= MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if files++; files > MaxFiles {
			return filepath.SkipAll
		}
		var found []string
		switch d.Name() {
		case "package.json":
			found = packageJSON(path)
		case "requirements.txt", "pyproject.toml", "go.mod":
			found = lineDeps(path)
		default:
			return nil
		}
		if len(found) == 0 {
			return nil
		}
		slices.Sort(found)
		found = slices.Compact(found)
		projectDir := filepath.Dir(path)
		out = append(out, Finding{Kind: KindAgentProject, Key: key(KindAgentProject, o.Host, projectDir), Attributes: map[string]string{
			"path": clip(projectDir), "manifest": d.Name(), "frameworks": clip(strings.Join(found, ",")), "host": clip(o.Host),
		}})
		return nil
	})
	return out
}

func packageJSON(path string) []string {
	doc := readJSON(path)
	var out []string
	for _, section := range []string{"dependencies", "devDependencies"} {
		if deps, ok := doc[section].(map[string]any); ok {
			for name := range deps {
				if f, ok := frameworks[name]; ok {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// lineDeps finds framework names at the start of dependency lines
// (requirements.txt, pyproject.toml, go.mod).
func lineDeps(path string) []string {
	f, err := os.Open(path) //nolint:gosec // G304: scanning the user's own project
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for lines := 0; sc.Scan() && lines < 5000; lines++ {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		line = strings.Trim(line, `"',`)
		line = strings.TrimPrefix(line, "require ")
		name := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" =<>~![;@\"'", r) })
		if len(name) == 0 {
			continue
		}
		if fw, ok := frameworks[name[0]]; ok {
			out = append(out, fw)
		}
	}
	return out
}

// secretKinds recognize credentials by their well-known prefix; the prefix
// is not secret and is all a finding shows of the value.
var secretKinds = []struct{ prefix, kind string }{
	{"pck_", "pantherclaw_api_key"},
	{"sk-ant-", "anthropic_api_key"},
	{"sk-proj-", "openai_api_key"},
	{"github_pat_", "github_token"},
	{"ghp_", "github_token"},
	{"gho_", "github_token"},
	{"xoxb-", "slack_token"},
	{"xoxp-", "slack_token"},
	{"AKIA", "aws_access_key_id"},
	{"AIza", "google_api_key"},
}

// secretNames recognize credentials by variable name when the value has
// no telling prefix.
var secretNames = map[string]string{ //nolint:gosec // G101: variable names, not credentials
	"OPENAI_API_KEY": "openai_api_key", "ANTHROPIC_API_KEY": "anthropic_api_key", "PANTHERCLAW_API_KEY": "pantherclaw_api_key",
	"GITHUB_TOKEN": "github_token", "GH_TOKEN": "github_token", "AWS_SECRET_ACCESS_KEY": "aws_secret_access_key",
}

// envSecrets reports NAME=value pairs that hold credentials, redacted.
func envSecrets(host, where string, env []string) []Finding {
	var out []Finding
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || len(value) < 8 {
			continue
		}
		kind, shown := "", ""
		for _, s := range secretKinds {
			if strings.HasPrefix(value, s.prefix) {
				kind, shown = s.kind, s.prefix
				break
			}
		}
		if kind == "" {
			if k, ok := secretNames[strings.ToUpper(name)]; ok {
				kind = k
			}
		}
		if kind == "" {
			continue
		}
		out = append(out, Finding{Kind: KindEnvSecret, Key: key(KindEnvSecret, host, where, name), Attributes: map[string]string{
			"name": clip(name), "secret_kind": kind, "where": clip(where), "redacted": shown + "…", "host": clip(host),
		}})
	}
	return out
}
