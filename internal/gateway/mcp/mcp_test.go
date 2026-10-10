// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"net/http"
	"strings"
	"testing"
)

// TestHR080_HeaderValuesDecode: plain values pass through; the base64
// sentinel form decodes to UTF-8; a broken one does not decode.
func TestHR080_HeaderValuesDecode(t *testing.T) {
	for in, want := range map[string]string{
		"create_refund":                       "create_refund",
		"=?base64?SGVsbG8sIOS4lueVjA==?=":     "Hello, 世界",
		"=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=": "=?base64?literal?=",
		"=?base64?missing-suffix":             "=?base64?missing-suffix",
	} {
		if got, ok := DecodeHeader(in); !ok || got != want {
			t.Errorf("%q = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"=?base64?!!!?=", "=?base64?/w==?="} {
		if _, ok := DecodeHeader(bad); ok {
			t.Errorf("%q decoded", bad)
		}
	}
}

// TestHR100_MCPRequestsAreParsedStrictly: one JSON-RPC 2.0 object with a
// string or number id, no unknown members, no duplicate names, bounded
// depth.
func TestHR100_MCPRequestsAreParsedStrictly(t *testing.T) {
	ok := `{"jsonrpc":"2.0","id":"a","method":"tools/list","params":{}}`
	if _, _, err := parse([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	deep := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + strings.Repeat(`{"a":`, 40) + `1` +
		strings.Repeat(`}`, 40) + `}}`
	for name, body := range map[string]string{
		"not json":        `{"jsonrpc":`,
		"wrong version":   `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
		"no method":       `{"jsonrpc":"2.0","id":1}`,
		"object id":       `{"jsonrpc":"2.0","id":{},"method":"tools/list"}`,
		"unknown member":  `{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":1}`,
		"duplicate names": `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}`,
		"array params":    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}`,
		"too deep":        deep,
	} {
		if _, _, err := parse([]byte(body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// FuzzMCPMessage: no body and header combination panics, and a request is
// accepted only when its headers equal its body.
func FuzzMCPMessage(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_refund","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"2026-07-28", "tools/call", "create_refund")
	f.Add(`[{"jsonrpc":"2.0"}]`, "", "", "")
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{}}}`, "2026-07-28", "tools/list", "=?base64?eA==?=")
	f.Fuzz(func(t *testing.T, body, version, method, name string) {
		req, p, err := parse([]byte(body))
		if err != nil {
			return
		}
		h := http.Header{}
		for k, v := range map[string]string{HeaderProtocolVersion: version, HeaderMethod: method, HeaderName: name} {
			if v != "" {
				h.Set(k, v)
			}
		}
		if headerMismatch(h, req, p) == "" && (method != req.Method || version != protocolVersion(p.Meta)) {
			t.Fatalf("accepted headers %q %q for method %q version %q", method, version, req.Method, protocolVersion(p.Meta))
		}
	})
}
