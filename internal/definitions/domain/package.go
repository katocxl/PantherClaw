// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Format is the only supported package format.
const Format = 1

// Package is a reviewed, versioned bundle of action definitions
// (F372, SemanticPackage).
type Package struct {
	Format      int          `json:"format"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Publisher   string       `json:"publisher"`
	Summary     string       `json:"summary"`
	Definitions []Definition `json:"definitions"`
}

// Channel is how an agent reaches a tool.
type Channel string

// Channels with mappings in part 1. SDK and hook channels reuse these
// mappings later (F099: the same effect gets the same decision).
const (
	ChannelMCP  Channel = "mcp"
	ChannelHTTP Channel = "http"
)

// Mapping maps one MCP tool or HTTP route onto the definition. Every
// expression is CEL over the request (internal/definitions/mapping); a wrong
// mapping is a total bypass, so mappings are reviewed as code and golden
// tested (HR-124).
type Mapping struct {
	Channel Channel `json:"channel"`
	Tool    string  `json:"tool,omitzero"`
	Method  string  `json:"method,omitzero"`
	Path    string  `json:"path,omitzero"`
	Route   string  `json:"route"`
	Extract Extract `json:"extract"`
}

// Extract holds the CEL expressions that produce the ActionIR fields.
type Extract struct {
	TargetID      string            `json:"target_id"`
	TargetAccount string            `json:"target_account,omitzero"`
	Params        map[string]string `json:"params"`
	Destinations  []DestinationExpr `json:"destinations,omitzero"`
}

// DestinationExpr classifies one destination (HR-079 groundwork).
type DestinationExpr struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

var (
	toolRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	varRe  = regexp.MustCompile(`\{[a-z0-9_]+\}`)
	// pathRe accepts reviewed templates such as /v1/charges/{charge}/refunds.
	pathRe    = regexp.MustCompile(`^(/([A-Za-z0-9._~-]+|\{[a-z][a-z0-9_]{0,31}\}))+$`)
	methods   = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	maxExpr   = 4 << 10
	patternMu sync.Mutex
	patterns  = map[string]*regexp.Regexp{}
)

// matches reports whether s matches a validated anchored pattern. Compiled
// patterns are cached; they come only from validated packages.
func matches(pattern, s string) bool {
	patternMu.Lock()
	re, ok := patterns[pattern]
	if !ok {
		var err error
		if re, err = regexp.Compile(pattern); err != nil {
			patternMu.Unlock()
			return false
		}
		patterns[pattern] = re
	}
	patternMu.Unlock()
	return re.MatchString(s)
}

// MatchID reports whether id is a valid target id for this definition.
func (t TargetSpec) MatchID(id string) bool { return matches(t.IDPattern, id) }

// MatchAccount reports whether account is valid: present exactly when the
// spec requires or allows it, and matching its pattern.
func (t TargetSpec) MatchAccount(account string) bool {
	switch {
	case account == "":
		return t.Account != PresenceRequired
	case t.Account == PresenceNone:
		return false
	default:
		return matches(t.AccountPattern, account)
	}
}

func expr(name, e string, required bool) error {
	switch {
	case e == "" && required:
		return invalid("%s: expression is required", name)
	case len(e) > maxExpr:
		return invalid("%s: expression longer than %d bytes", name, maxExpr)
	}
	return nil
}

func (d *Definition) validateMapping(i int) error {
	m := d.Mappings[i]
	at := fmt.Sprintf("%s: mappings[%d]", d.Operation, i)
	switch m.Channel {
	case ChannelMCP:
		if !toolRe.MatchString(m.Tool) || m.Method != "" || m.Path != "" {
			return invalid("%s: an mcp mapping names a tool and no method or path", at)
		}
	case ChannelHTTP:
		if m.Tool != "" || !slices.Contains(methods, m.Method) || !pathRe.MatchString(m.Path) || len(m.Path) > 512 {
			return invalid("%s: an http mapping names a method %v and a path template", at, methods)
		}
		for seg := range strings.SplitSeq(m.Path[1:], "/") {
			if seg == "." || seg == ".." {
				return invalid("%s: dot segments are not allowed in path templates", at)
			}
		}
		vars := varRe.FindAllString(m.Path, -1)
		for j, v := range vars {
			if slices.Contains(vars[:j], v) {
				return invalid("%s: path variable %s appears twice", at, v)
			}
		}
	default:
		return invalid("%s: channel must be mcp or http", at)
	}
	if !actionir.ValidRoute(m.Route) {
		return invalid("%s: route %q", at, m.Route)
	}
	x := m.Extract
	if err := expr(at+".target_id", x.TargetID, true); err != nil {
		return err
	}
	if err := expr(at+".target_account", x.TargetAccount, d.Target.Account == PresenceRequired); err != nil {
		return err
	}
	if x.TargetAccount != "" && d.Target.Account == PresenceNone {
		return invalid("%s: target_account for a target without an account", at)
	}
	for _, name := range slices.Sorted(maps.Keys(x.Params)) {
		if _, ok := d.Params[name]; !ok {
			return invalid("%s: extracts undeclared param %q", at, name)
		}
		if err := expr(at+".params."+name, x.Params[name], true); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(d.Params)) {
		if _, ok := x.Params[name]; !ok && d.Params[name].Required {
			return invalid("%s: does not extract required param %q", at, name)
		}
	}
	if len(x.Destinations) > maxItems {
		return invalid("%s: at most %d destinations", at, maxItems)
	}
	for _, dst := range x.Destinations {
		if (dst.Kind != "internal" && dst.Kind != "external") || expr(at+".destinations", dst.ID, true) != nil {
			return invalid("%s: destinations need kind internal|external and an id expression", at)
		}
	}
	return nil
}

// Validate checks the whole package. Definitions are validated one by one,
// then the cross-references: unique operations, tools and routes, and
// verifier operations that are reads in this package.
func (p *Package) Validate() error {
	switch {
	case p.Format != Format:
		return invalid("unsupported format %d", p.Format)
	case !actionir.ValidPackage(p.Name):
		return invalid("package name %q", p.Name)
	case !actionir.ValidVersion(p.Version):
		return invalid("version %q must be MAJOR.MINOR.PATCH", p.Version)
	case !reviewRe.MatchString(p.Publisher):
		return invalid("publisher %q", p.Publisher)
	case len(p.Definitions) == 0 || len(p.Definitions) > 256:
		return invalid("a package has 1..256 definitions")
	}
	if err := text("summary", p.Summary); err != nil {
		return err
	}
	ops := map[string]*Definition{}
	routes := map[string]string{}
	for i := range p.Definitions {
		d := &p.Definitions[i]
		if err := d.Validate(); err != nil {
			return err
		}
		if ops[d.Operation] != nil {
			return invalid("duplicate operation %s", d.Operation)
		}
		ops[d.Operation] = d
		for _, m := range d.Mappings {
			key := string(m.Channel) + " " + m.Tool + m.Method + " " + varRe.ReplaceAllString(m.Path, "{}")
			if prev, dup := routes[key]; dup {
				return invalid("%s and %s both map %s", prev, d.Operation, key)
			}
			routes[key] = d.Operation
		}
	}
	for _, d := range p.Definitions {
		if v := d.Verifier; v != nil && (ops[v.Operation] == nil || ops[v.Operation].Access != AccessRead) {
			return invalid("%s: verifier %s must be a read operation in this package", d.Operation, v.Operation)
		}
	}
	return nil
}

// Definition returns the definition of op.
func (p *Package) Definition(op string) (*Definition, bool) {
	i := slices.IndexFunc(p.Definitions, func(d Definition) bool { return d.Operation == op })
	if i < 0 {
		return nil, false
	}
	return &p.Definitions[i], true
}

// Version is a parsed MAJOR.MINOR.PATCH package version.
type Version [3]int

// ParseVersion parses a package version.
func ParseVersion(s string) (Version, error) {
	if !actionir.ValidVersion(s) {
		return Version{}, invalid("version %q must be MAJOR.MINOR.PATCH", s)
	}
	var v Version
	for i, part := range strings.Split(s, ".") {
		v[i], _ = strconv.Atoi(part)
	}
	return v, nil
}

// Compare returns -1, 0 or +1.
func (v Version) Compare(o Version) int { return slices.Compare(v[:], o[:]) }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }
