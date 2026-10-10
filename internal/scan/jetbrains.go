// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"bytes"
	"cmp"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// JetBrains AI Assistant (the AI Assistant plugin, MCP client since 2025.1;
// Junie is a separate client) keeps its MCP servers in these places:
//
//   - IDE level: options/llm.mcpServers.xml in each IDE's configuration
//     directory, <config>/JetBrains/<Product><Version>, where <config> is
//     %APPDATA% on Windows, ~/Library/Application Support on macOS and
//     $XDG_CONFIG_HOME or ~/.config on Linux, as os.UserConfigDir returns.
//     Every installed IDE and version has its own. Sources: "Directories used
//     by the IDE", https://www.jetbrains.com/help/idea/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html#config-directory,
//     which JetBrains named as the store for these servers in
//     https://youtrack.jetbrains.com/issue/LLM-16145; the file name from
//     https://youtrack.jetbrains.com/issue/LLM-22682
//     (PhpStorm2025.3/options/llm.mcpServers.xml) and copies committed to
//     dotfiles repositories (PyCharm2026.1, CLion2025.3, RustRover2025.3).
//   - Project level: .idea/workspace.xml (LLM-16145), or
//     .idea/.idea.<Solution>/.idea/workspace.xml for Rider, as committed
//     Rider projects show.
//   - Since 2025.3 the definitions are JSON in the mcpServers form, in
//     ~/.ai/mcp/mcp.json (LLM-22682, PhpStorm 2025.3) and
//     <project>/.ai/mcp/mcp.json (https://youtrack.jetbrains.com/issue/LLM-26654,
//     PhpStorm 2026.1), and the XML keeps only each server's name and state.
//
// The XML component is McpApplicationServerCommands in llm.mcpServers.xml
// and McpProjectServerCommands in workspace.xml. Its entries have had two
// layouts, and each entry is read the same way in both:
//
//	<component name="McpProjectServerCommands">
//	  <McpServerCommand>                      2025.1: entries in the component
//	    <option name="name" value="nx-mcp" />
//	    <option name="programPath" value="npx.cmd" />
//	    <option name="arguments" value="-y nx-mcp@latest" />
//	    <envs><env name="TOKEN" value="…" /></envs>
//	  </McpServerCommand>
//	  <commands>…</commands>                  later: local servers
//	  <urls>…</urls>                          later: remote servers
//	</component>
//
// Sources: committed workspace.xml files of both layouts (the first as Nx
// Console's AI Assistant setup writes it), and the 10.0.0 notes of the "MCP
// Servers for AI Assistants" plugin, which writes both. An entry's options
// and its environment and header lists are read at any depth, so the
// element names of later versions are not relied on. From 2025.3 the
// entries are McpServerConfigurationProperties holding only state ("name",
// "enabled", "allowedToolsNames"); an entry with neither a command nor a
// URL is skipped, since that server is read from .ai/mcp/mcp.json.

// jetBrainsComponents name the AI Assistant's MCP component in the IDE's
// llm.mcpServers.xml and in a project's workspace.xml.
var jetBrainsComponents = []string{"McpApplicationServerCommands", "McpProjectServerCommands"}

// jetBrainsConfigs lists the AI Assistant files of every IDE and version in
// dir (<config>/JetBrains).
func jetBrainsConfigs(dir string) []string {
	var out []string
	for _, ide := range entries(dir, "") {
		out = append(out, filepath.Join(ide, "options", "llm.mcpServers.xml"))
	}
	return out
}

// jetBrainsWorkspaces lists a project's workspace.xml files: .idea's, and
// Rider's per solution.
func jetBrainsWorkspaces(project string) []string {
	idea := filepath.Join(project, ".idea")
	out := []string{filepath.Join(idea, "workspace.xml")}
	for _, sln := range entries(idea, ".idea.") {
		out = append(out, filepath.Join(sln, ".idea", "workspace.xml"))
	}
	return out
}

// entries lists the paths in dir whose names start with prefix, sorted. They
// are not checked to be directories, so a symlinked IDE directory is kept;
// reading a file under a non-directory fails later.
func entries(dir, prefix string) []string {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, de := range des {
		if strings.HasPrefix(de.Name(), prefix) {
			out = append(out, filepath.Join(dir, de.Name()))
		}
	}
	return out
}

// fromJetBrainsXML reads the AI Assistant's MCP servers from an XML options
// file into the mcpServers form of the JSON clients, or returns nil for a
// file that is not well formed.
func fromJetBrainsXML(b []byte) map[string]any {
	doc := parseXML(b)
	if doc == nil {
		return nil
	}
	var list []*xmlNode
	for _, top := range doc.kids { // <application> or <project>
		for _, c := range top.kids {
			if v, _ := c.attr("name"); c.name != "component" || !slices.Contains(jetBrainsComponents, v) {
				continue
			}
			for _, e := range c.kids {
				if e.name == "commands" || e.name == "urls" {
					list = append(list, e.kids...)
				} else {
					list = append(list, e)
				}
			}
		}
	}
	servers := map[string]any{}
	for _, e := range list {
		if name, s := jetBrainsServer(e); s != nil {
			servers[name] = s
		}
	}
	return map[string]any{"mcpServers": servers}
}

// jetBrainsServer reads one entry into the JSON form: its options (the first
// of each name) and the name/value pairs under an environment or header list
// (<envs><env name value/>, an <option name="env"> map of <entry key value/>,
// <headers>). It returns nil for an entry with no name, or with neither a
// command nor a URL. The arguments are not read: tokens are passed there.
func jetBrainsServer(e *xmlNode) (string, map[string]any) {
	opts := map[string]string{}
	env, headers := map[string]any{}, map[string]any{}
	var walk func(n *xmlNode, list map[string]any)
	walk = func(n *xmlNode, list map[string]any) {
		label := n.name
		if n.name == "option" {
			label, _ = n.attr("name")
		}
		k, v, ok := n.pair()
		switch {
		case list != nil:
			if ok {
				list[k] = v
			}
		case label == "envs" || label == "env" || label == "environment":
			list = env
		case label == "headers":
			list = headers
		case n.name == "option" && ok:
			if _, seen := opts[k]; !seen {
				opts[k] = v
			}
		}
		for _, kid := range n.kids {
			walk(kid, list)
		}
	}
	walk(e, nil)
	s := map[string]any{}
	if cmd := cmp.Or(opts["programPath"], opts["command"]); cmd != "" {
		s["command"] = cmd
	}
	if u := cmp.Or(opts["url"], opts["serverUrl"]); u != "" {
		s["url"] = u
	}
	if opts["name"] == "" || len(s) == 0 {
		return "", nil
	}
	if len(env) > 0 {
		s["env"] = env
	}
	if len(headers) > 0 {
		s["headers"] = headers
	}
	return opts["name"], s
}

// xmlNode is one element of an XML document.
type xmlNode struct {
	name  string
	attrs []xml.Attr
	kids  []*xmlNode
}

func (n *xmlNode) attr(name string) (string, bool) {
	for _, a := range n.attrs {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// pair reads a name="…" (or key="…") value="…" element.
func (n *xmlNode) pair() (k, v string, ok bool) {
	k, _ = n.attr("name")
	if k == "" {
		k, _ = n.attr("key")
	}
	v, ok = n.attr("value")
	return k, v, ok && k != ""
}

// parseXML reads an XML document into a tree under an unnamed root, or
// returns nil for one that is not well formed or is nested deeper than
// MaxNesting (HR-100). encoding/xml reads no DTD and expands only the five
// predefined entities, so a document can neither include a file nor grow by
// entity expansion; any other entity is an error.
func parseXML(b []byte) *xmlNode {
	d := xml.NewDecoder(bytes.NewReader(b))
	stack := []*xmlNode{{}}
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > MaxNesting {
				return nil
			}
			n := &xmlNode{name: t.Name.Local, attrs: t.Copy().Attr}
			parent := stack[len(stack)-1]
			parent.kids = append(parent.kids, n)
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 1 {
		return nil
	}
	return stack[0]
}
