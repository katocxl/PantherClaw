// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mcpheader is the request metadata MCP 2026-07-28 mirrors from
// tool arguments into HTTP headers (Streamable HTTP, Custom Headers from
// Tool Parameters): the x-mcp-header declarations of a tool's input
// schema, the Mcp-Param-{Name} headers a client sends for a call, and the
// check a server makes that those headers equal the body (HR-080, T-019).
// A value that is not plain header-safe ASCII travels in the base64
// sentinel form "=?base64?…?=", which Mcp-Name shares. Parsing is strict
// and bounded (HR-100).
package mcpheader

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Prefix starts the name of every parameter header.
const Prefix = "Mcp-Param-"

// Bounds (HR-100).
const (
	// MaxParams bounds a tool's x-mcp-header declarations.
	MaxParams = 32
	// MaxName bounds an x-mcp-header value.
	MaxName = 64
	// maxPath bounds the properties from the schema root to a declaration.
	maxPath = 16
	// maxSafe is the largest integer a header may carry (2^53-1).
	maxSafe = 1<<53 - 1
)

// ErrInvalid reports x-mcp-header declarations that break the
// specification's constraints. Such a tool is invalid: a client leaves it
// out of its tool list and never calls it.
var ErrInvalid = errors.New("invalid x-mcp-header declaration")

// Param is one x-mcp-header declaration: the argument at Path (property
// names from the schema root) is mirrored into the header Prefix+Name.
type Param struct {
	Name string
	Path []string
	// Type is the property's type: string, integer or boolean.
	Type string
}

// Header is the name of the parameter's header.
func (p Param) Header() string { return Prefix + p.Name }

const (
	sentinelStart = "=?base64?"
	sentinelEnd   = "?="
)

func sentinel(v string) bool {
	return strings.HasPrefix(v, sentinelStart) && strings.HasSuffix(v, sentinelEnd)
}

// Encode is the header value for s (Value Encoding): s itself when it is
// non-empty printable ASCII without leading or trailing spaces and does
// not look like the sentinel form, otherwise the sentinel form of its
// UTF-8 bytes.
func Encode(s string) string {
	plain := s != "" && s == strings.TrimSpace(s) && !sentinel(s)
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			plain = false
		}
	}
	if plain {
		return s
	}
	return sentinelStart + base64.StdEncoding.EncodeToString([]byte(s)) + sentinelEnd
}

// Decode is the value a header carries: a plain value of printable ASCII
// as it is, or the sentinel form decoded strictly to valid UTF-8. ok is
// false for anything else, which the server refuses.
func Decode(v string) (string, bool) {
	for i := range len(v) {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "", false
		}
	}
	if !sentinel(v) {
		return v, true
	}
	inner, ok := strings.CutSuffix(strings.TrimPrefix(v, sentinelStart), sentinelEnd)
	if !ok {
		// "=?base64?=": the markers overlap.
		return "", false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(inner)
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// Parse returns the x-mcp-header declarations of an input schema, sorted
// by path. Each must be an HTTP token of at most MaxName bytes, unique
// ignoring case, on a property of type string, integer or boolean that is
// statically reachable from the root: through properties only, never
// items, composition, conditionals, definitions or $ref. An x-mcp-header
// member anywhere else makes the schema invalid (ErrInvalid).
func Parse(schema jsontext.Value) ([]Param, error) {
	var out []Param
	if err := walk(schema, true, nil, &out); err != nil {
		return nil, err
	}
	if len(out) > MaxParams {
		return nil, fmt.Errorf("%w: more than %d", ErrInvalid, MaxParams)
	}
	seen := map[string]bool{}
	for _, p := range out {
		k := strings.ToLower(p.Name)
		if seen[k] {
			return nil, fmt.Errorf("%w: %q is declared twice", ErrInvalid, p.Name)
		}
		seen[k] = true
	}
	return out, nil
}

// walk visits one schema node. reachable says whether the node is reached
// from the root through properties only, and path is how.
func walk(v jsontext.Value, reachable bool, path []string, out *[]Param) error {
	if v.Kind() == '[' {
		var items []jsontext.Value
		if err := json.Unmarshal(v, &items); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		for _, it := range items {
			if err := walk(it, false, path, out); err != nil {
				return err
			}
		}
		return nil
	}
	if v.Kind() != '{' {
		return nil
	}
	var m map[string]jsontext.Value
	if err := json.Unmarshal(v, &m); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		switch {
		case k == "x-mcp-header":
			p, err := declare(m[k], m["type"], reachable, path)
			if err != nil {
				return err
			}
			*out = append(*out, p)
		case k == "properties" && m[k].Kind() == '{':
			var props map[string]jsontext.Value
			if err := json.Unmarshal(m[k], &props); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalid, err)
			}
			for _, name := range slices.Sorted(maps.Keys(props)) {
				if err := walk(props[name], reachable && len(path) < maxPath, append(slices.Clip(path), name), out); err != nil {
					return err
				}
			}
		default:
			// Every other keyword, and anything inside an instance value
			// (const, default, enum, examples), is not reachable.
			if err := walk(m[k], false, path, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func declare(name, typ jsontext.Value, reachable bool, path []string) (Param, error) {
	var n, t string
	if name.Kind() != '"' || json.Unmarshal(name, &n) != nil {
		return Param{}, fmt.Errorf("%w: the value is not a string", ErrInvalid)
	}
	switch {
	case !reachable || len(path) == 0:
		return Param{}, fmt.Errorf("%w: %q is not on a property reachable from the root through properties", ErrInvalid, n)
	case n == "" || len(n) > MaxName || !token(n):
		return Param{}, fmt.Errorf("%w: %q is not an HTTP token of at most %d bytes", ErrInvalid, n, MaxName)
	case typ.Kind() != '"' || json.Unmarshal(typ, &t) != nil || (t != "string" && t != "integer" && t != "boolean"):
		return Param{}, fmt.Errorf("%w: %q is not on a string, integer or boolean property", ErrInvalid, n)
	}
	return Param{Name: n, Path: path, Type: t}, nil
}

// token reports whether s is 1*tchar (RFC 9110 §5.6.2).
func token(s string) bool {
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Mirror returns the headers a client sends with a call's arguments (a
// JSON object): one per declaration whose argument is present and not
// null, encoded. An argument of another type than declared, or an integer
// outside ±(2^53-1), cannot be mirrored and is an error.
func Mirror(params []Param, args jsontext.Value) (http.Header, error) {
	root := object(args)
	h := http.Header{}
	for _, p := range params {
		v, ok := lookup(root, p.Path)
		if !ok {
			continue
		}
		s, ok := text(p.Type, v)
		if !ok {
			return nil, fmt.Errorf("mcpheader: the argument for %s is not a %s header value", p.Header(), p.Type)
		}
		h.Set(p.Header(), Encode(s))
	}
	return h, nil
}

// Check reports how a request's parameter headers differ from its
// arguments, or "" when they agree: every declared argument that is
// present and not null has its header, once, equal to it after decoding
// (integers compared as numbers); no header names an argument the body
// leaves out, or one the tool does not declare (HR-080).
func Check(h http.Header, params []Param, args jsontext.Value) string {
	for _, name := range slices.Sorted(maps.Keys(h)) {
		if len(name) >= len(Prefix) && strings.EqualFold(name[:len(Prefix)], Prefix) &&
			!slices.ContainsFunc(params, func(p Param) bool { return strings.EqualFold(p.Header(), name) }) {
			return name + " header for a parameter the tool does not declare"
		}
	}
	root := object(args)
	for _, p := range params {
		var vs []string
		for k, v := range h {
			if strings.EqualFold(k, p.Header()) {
				vs = append(vs, v...)
			}
		}
		v, present := lookup(root, p.Path)
		switch {
		case !present && len(vs) == 0:
			continue
		case !present:
			return p.Header() + " header for an argument the body does not carry"
		case len(vs) == 0:
			return p.Header() + " header is missing"
		case len(vs) > 1:
			return p.Header() + " header is repeated"
		}
		got, ok := Decode(vs[0])
		if !ok {
			return p.Header() + " header is not a valid value"
		}
		if want, ok := text(p.Type, v); !ok || !equal(p.Type, got, want) {
			return p.Header() + " header does not match the body"
		}
	}
	return ""
}

// equal compares a decoded header value with the body's, as text, or as
// numbers for an integer (42.0 equals 42).
func equal(typ, got, want string) bool {
	if typ != "integer" {
		return got == want
	}
	n, ok := integer(got)
	return ok && strconv.FormatInt(n, 10) == want
}

// object decodes the members of a JSON object; anything else has none.
func object(v jsontext.Value) map[string]jsontext.Value {
	var m map[string]jsontext.Value
	if v.Kind() != '{' || json.Unmarshal(v, &m) != nil {
		return nil
	}
	return m
}

// lookup is the value at path, false when it is absent or null.
func lookup(root map[string]jsontext.Value, path []string) (jsontext.Value, bool) {
	m := root
	var v jsontext.Value
	for i, name := range path {
		var ok bool
		if v, ok = m[name]; !ok {
			return nil, false
		}
		if i < len(path)-1 {
			if m = object(v); m == nil {
				return nil, false
			}
		}
	}
	if len(v) == 0 || v.Kind() == 'n' {
		return nil, false
	}
	return v, true
}

// text is an argument's header text for its declared type: a string as
// it is, an integer in decimal, a boolean as true or false.
func text(typ string, v jsontext.Value) (string, bool) {
	switch {
	case typ == "string" && v.Kind() == '"':
		var s string
		return s, json.Unmarshal(v, &s) == nil
	case typ == "boolean" && (v.Kind() == 't' || v.Kind() == 'f'):
		return string(v), true
	case typ == "integer" && v.Kind() == '0':
		n, ok := integer(string(v))
		return strconv.FormatInt(n, 10), ok
	}
	return "", false
}

// integer reads a decimal integer within ±(2^53-1): an optional minus,
// digits without leading zeros, and optionally a fraction of zeros.
func integer(s string) (int64, bool) {
	if whole, frac, ok := strings.Cut(s, "."); ok {
		if frac == "" || strings.Trim(frac, "0") != "" {
			return 0, false
		}
		s = whole
	}
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || len(digits) > 16 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxSafe || n < -maxSafe {
		return 0, false
	}
	return n, true
}
