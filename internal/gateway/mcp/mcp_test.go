// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
)

// TestHR080_MCPNameDecodes: Mcp-Name matches the body plain or in the
// base64 sentinel form; a broken or non-UTF-8 form, raw non-ASCII or
// another name does not.
func TestHR080_MCPNameDecodes(t *testing.T) {
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	name := "cr" + string(rune(0xe9)) + "er_remboursement"
	req, p, err := parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `",` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	h := func(n string) http.Header {
		return headers(HeaderProtocolVersion, ProtocolVersion, HeaderMethod, "tools/call", HeaderName, n)
	}
	if msg := headerMismatch(h(b64(name)), req, p, nil); msg != "" {
		t.Fatalf("base64 Mcp-Name: %s", msg)
	}
	for _, bad := range []string{name, "=?base64?!!!?=", "=?base64?/w==?=", b64("creer_remboursement")} {
		if headerMismatch(h(bad), req, p, nil) == "" {
			t.Errorf("Mcp-Name %q accepted", bad)
		}
	}
}

// refundSchema is a reviewed input schema that marks the currency and a
// nested flag for Mcp-Param-* headers.
func refundSchema() *domain.Schema {
	no := false
	return &domain.Schema{Type: "object", AdditionalProperties: &no, Properties: map[string]*domain.Schema{
		"charge":   {Type: "string"},
		"currency": {Type: "string", Enum: []string{"USD", "EUR"}, Header: "Currency"},
		"options": {Type: "object", AdditionalProperties: &no, Properties: map[string]*domain.Schema{
			"notify": {Type: "boolean", Header: "Notify"},
		}},
	}}
}

// TestHR080_ServedSchemasDeclareTheCheckedHeaders: the parameters the face
// checks are exactly those a client reads, by the specification's rules,
// from the schema it is served.
func TestHR080_ServedSchemasDeclareTheCheckedHeaders(t *testing.T) {
	served, err := json.Marshal(refundSchema())
	if err != nil {
		t.Fatal(err)
	}
	read, err := mcpheader.Parse(served)
	got := headerParams(refundSchema())
	same := func(a, b mcpheader.Param) bool {
		return a.Name == b.Name && a.Type == b.Type && slices.Equal(a.Path, b.Path)
	}
	if err != nil || len(got) != 2 || !slices.EqualFunc(got, read, same) {
		t.Fatalf("checked %+v, a client reads %+v %v", got, read, err)
	}
	if headerParams(nil) != nil {
		t.Fatal("a tool without a schema declares headers")
	}
}

// TestHR080_ParamHeadersAreCheckedOnToolCallsOnly: on tools/call the
// declared Mcp-Param-* headers must equal the arguments, and none may be
// missing, extra or broken; any other method takes none.
func TestHR080_ParamHeadersAreCheckedOnToolCallsOnly(t *testing.T) {
	declared := headerParams(refundSchema())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund",` +
		`"arguments":{"charge":"ch_1","currency":"USD","options":{"notify":true}},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, p, err := parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	with := func(extra map[string]string) http.Header {
		h := headers(HeaderProtocolVersion, ProtocolVersion, HeaderMethod, "tools/call", HeaderName, "create_refund")
		for k, v := range extra {
			h.Set(k, v)
		}
		return h
	}
	good := map[string]string{"Mcp-Param-Currency": "USD", "Mcp-Param-Notify": "true"}
	if msg := headerMismatch(with(good), req, p, declared); msg != "" {
		t.Fatalf("matching headers: %s", msg)
	}
	for name, hdr := range map[string]map[string]string{
		"none":             nil,
		"no Notify":        {"Mcp-Param-Currency": "USD"},
		"another currency": {"Mcp-Param-Currency": "EUR", "Mcp-Param-Notify": "true"},
		"an extra header":  {"Mcp-Param-Currency": "USD", "Mcp-Param-Notify": "true", "Mcp-Param-Charge": "ch_1"},
		"broken base64":    {"Mcp-Param-Currency": "=?base64?***?=", "Mcp-Param-Notify": "true"},
	} {
		if msg := headerMismatch(with(hdr), req, p, declared); !strings.Contains(msg, "Mcp-Param-") {
			t.Errorf("%s: %q", name, msg)
		}
	}
	list, lp, err := parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	h := headers(HeaderProtocolVersion, ProtocolVersion, HeaderMethod, "tools/list", "Mcp-Param-Currency", "USD")
	if headerMismatch(h, list, lp, nil) == "" {
		t.Error("an Mcp-Param header on tools/list: accepted")
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
// accepted only when its headers equal its body, Mcp-Param-Currency
// included.
func FuzzMCPMessage(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_refund","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		"2026-07-28", "tools/call", "create_refund", "")
	f.Add(`[{"jsonrpc":"2.0"}]`, "", "", "", "")
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{}}}`, "2026-07-28", "tools/list", "=?base64?eA==?=", "")
	f.Add(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_refund","arguments":{"currency":"USD"},`+
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, "2026-07-28", "tools/call", "create_refund", "=?base64?VVNE?=")
	declared := headerParams(refundSchema())[:1]
	f.Fuzz(func(t *testing.T, body, version, method, name, currency string) {
		req, p, err := parse([]byte(body))
		if err != nil {
			return
		}
		h := http.Header{}
		for k, v := range map[string]string{HeaderProtocolVersion: version, HeaderMethod: method, HeaderName: name, "Mcp-Param-Currency": currency} {
			if v != "" {
				h.Set(k, v)
			}
		}
		if headerMismatch(h, req, p, declared) != "" {
			return
		}
		if method != req.Method || version != protocolVersion(p.Meta) {
			t.Fatalf("accepted headers %q %q for method %q version %q", method, version, req.Method, protocolVersion(p.Meta))
		}
		var args map[string]jsontext.Value
		_ = json.Unmarshal(p.Arguments, &args)
		arg := args["currency"]
		present := len(arg) > 0 && arg.Kind() != 'n'
		var want string
		if present && json.Unmarshal(arg, &want) != nil {
			t.Fatalf("accepted a currency header for the argument %s", arg)
		}
		if got, ok := mcpheader.Decode(currency); present != (currency != "") || (present && (!ok || got != want)) {
			t.Fatalf("accepted Mcp-Param-Currency %q for the argument %s", currency, arg)
		}
	})
}

// headers sets name, value pairs.
func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}
