// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpheader

import (
	"encoding/json/jsontext"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestHR080_ParameterValuesEncode: the specification's encoding examples;
// plain printable ASCII passes through, anything else (non-ASCII, control
// characters, outer spaces, the empty string, the sentinel pattern) is
// base64, and decoding gives the value back.
func TestHR080_ParameterValuesEncode(t *testing.T) {
	for in, want := range map[string]string{
		"us-west1":           "us-west1",
		"Hello, 世界":          "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":           "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":       "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"=?base64?=":         "=?base64?PT9iYXNlNjQ/PQ==?=",
		"tab\there":          "=?base64?dGFiCWhlcmU=?=",
		"":                   "=?base64??=",
		"a b":                "a b",
	} {
		got := Encode(in)
		if got != want {
			t.Errorf("Encode(%q) = %q, want %q", in, got, want)
		}
		if back, ok := Decode(got); !ok || back != in {
			t.Errorf("Decode(%q) = %q %v, want %q", got, back, ok, in)
		}
	}
	if got, ok := Decode("=?base64?missing-suffix"); !ok || got != "=?base64?missing-suffix" {
		t.Errorf("a value that only starts like the sentinel = %q %v", got, ok)
	}
	for _, bad := range []string{
		"=?base64?!!!?=",           // not base64
		"=?base64?/w==?=",          // not UTF-8
		"=?base64?SGk?=",           // no padding
		"=?base64?SGl=?=",          // non-canonical trailing bits
		"=?base64?=",               // the markers overlap
		"caf" + string(rune(0xe9)), // raw non-ASCII
		"a\tb",                     // a raw control character
		"a" + string(rune(0x7f)),
	} {
		if v, ok := Decode(bad); ok {
			t.Errorf("Decode(%q) = %q", bad, v)
		}
	}
}

// TestHR080_ToolsDeclareParameterHeaders: x-mcp-header declarations are
// read from properties reached through properties only, on strings,
// integers and booleans, as HTTP tokens unique ignoring case; anything
// else makes the tool invalid (the specification's constraints).
func TestHR080_ToolsDeclareParameterHeaders(t *testing.T) {
	example := `{"type":"object","properties":{` +
		`"region":{"type":"string","description":"The region to execute the query in","x-mcp-header":"Region"},` +
		`"query":{"type":"string"},` +
		`"opts":{"type":"object","properties":{"limit":{"type":"integer","x-mcp-header":"Limit"},"dry":{"type":"boolean","x-mcp-header":"Dry-Run"}}},` +
		`"x-mcp-header":{"type":"string"}},` +
		`"required":["region","query"]}`
	got, err := Parse(jsontext.Value(example))
	want := []Param{
		{Name: "Dry-Run", Path: []string{"opts", "dry"}, Type: "boolean"},
		{Name: "Limit", Path: []string{"opts", "limit"}, Type: "integer"},
		{Name: "Region", Path: []string{"region"}, Type: "string"},
	}
	if err != nil || !slices.EqualFunc(got, want, func(a, b Param) bool {
		return a.Name == b.Name && a.Type == b.Type && slices.Equal(a.Path, b.Path)
	}) {
		t.Fatalf("Parse = %+v %v, want %+v", got, err, want)
	}
	if got, err := Parse(jsontext.Value(`{"type":"object","properties":{"q":{"type":"string"}}}`)); err != nil || got != nil {
		t.Fatalf("no declarations = %+v %v", got, err)
	}
	prop := func(schema string) string { return `{"type":"object","properties":{"p":` + schema + `}}` }
	many := `{"type":"object","properties":{`
	for i := range MaxParams + 1 {
		many += `"p` + strconv.Itoa(i) + `":{"type":"string","x-mcp-header":"P` + strconv.Itoa(i) + `"},`
	}
	many = strings.TrimSuffix(many, ",") + `}}`
	for name, schema := range map[string]string{
		"empty":           prop(`{"type":"string","x-mcp-header":""}`),
		"a space":         prop(`{"type":"string","x-mcp-header":"Re gion"}`),
		"a colon":         prop(`{"type":"string","x-mcp-header":"Re:gion"}`),
		"a line feed":     prop(`{"type":"string","x-mcp-header":"Re\ngion"}`),
		"non-ASCII":       prop(`{"type":"string","x-mcp-header":"Régión"}`),
		"too long":        prop(`{"type":"string","x-mcp-header":"` + strings.Repeat("a", MaxName+1) + `"}`),
		"not a string":    prop(`{"type":"string","x-mcp-header":7}`),
		"a number":        prop(`{"type":"number","x-mcp-header":"N"}`),
		"an object":       prop(`{"type":"object","x-mcp-header":"N"}`),
		"an array":        prop(`{"type":"array","items":{"type":"string"},"x-mcp-header":"N"}`),
		"no type":         prop(`{"x-mcp-header":"N"}`),
		"a type list":     prop(`{"type":["string","null"],"x-mcp-header":"N"}`),
		"on the root":     `{"type":"object","x-mcp-header":"Root","properties":{}}`,
		"in items":        prop(`{"type":"array","items":{"type":"string","x-mcp-header":"N"}}`),
		"in prefixItems":  prop(`{"type":"array","prefixItems":[{"type":"string","x-mcp-header":"N"}]}`),
		"in oneOf":        prop(`{"oneOf":[{"type":"string","x-mcp-header":"N"}]}`),
		"in anyOf":        prop(`{"anyOf":[{"type":"string","x-mcp-header":"N"}]}`),
		"in allOf":        `{"type":"object","allOf":[{"properties":{"p":{"type":"string","x-mcp-header":"N"}}}]}`,
		"in not":          prop(`{"not":{"type":"string","x-mcp-header":"N"}}`),
		"in then":         `{"type":"object","if":{},"then":{"properties":{"p":{"type":"string","x-mcp-header":"N"}}}}`,
		"in $defs":        `{"type":"object","$defs":{"d":{"type":"string","x-mcp-header":"N"}},"properties":{"p":{"$ref":"#/$defs/d"}}}`,
		"in patternProps": `{"type":"object","patternProperties":{"^p":{"type":"string","x-mcp-header":"N"}}}`,
		"in additional":   `{"type":"object","additionalProperties":{"type":"string","x-mcp-header":"N"}}`,
		"twice":           `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"string","x-mcp-header":"region"}}}`,
		"too many":        many,
		"too deep":        strings.Repeat(`{"type":"object","properties":{"p":`, maxPath+1) + `{"type":"string","x-mcp-header":"Deep"}` + strings.Repeat(`}}`, maxPath+1),
	} {
		if got, err := Parse(jsontext.Value(schema)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse = %+v %v", name, got, err)
		}
	}
}

var region = []Param{
	{Name: "Region", Path: []string{"region"}, Type: "string"},
	{Name: "Limit", Path: []string{"opts", "limit"}, Type: "integer"},
	{Name: "Dry-Run", Path: []string{"dry"}, Type: "boolean"},
}

// TestHR080_ArgumentsAreMirrored: each declared argument that is present
// and not null becomes its header, encoded; an absent or null one is left
// out; an argument of another type, or an unsafe integer, is an error.
func TestHR080_ArgumentsAreMirrored(t *testing.T) {
	h, err := Mirror(region, jsontext.Value(`{"region":"us-west1","opts":{"limit":42.0},"dry":false,"query":"SELECT 1"}`))
	if err != nil || h.Get("Mcp-Param-Region") != "us-west1" || h.Get("Mcp-Param-Limit") != "42" || h.Get("Mcp-Param-Dry-Run") != "false" ||
		len(h) != 3 {
		t.Fatalf("Mirror = %v %v", h, err)
	}
	h, err = Mirror(region, jsontext.Value(`{"region":"Hello, 世界","opts":{"limit":null}}`))
	if err != nil || h.Get("Mcp-Param-Region") != "=?base64?SGVsbG8sIOS4lueVjA==?=" || len(h) != 1 {
		t.Fatalf("Mirror with null and absent = %v %v", h, err)
	}
	if h, err := Mirror(region, jsontext.Value(`{"opts":"not an object"}`)); err != nil || len(h) != 0 {
		t.Fatalf("Mirror through a non-object = %v %v", h, err)
	}
	for _, args := range []string{
		`{"region":7}`,
		`{"dry":"false"}`,
		`{"opts":{"limit":"42"}}`,
		`{"opts":{"limit":4.5}}`,
		`{"opts":{"limit":1e2}}`,
		`{"opts":{"limit":9007199254740992}}`,
	} {
		if h, err := Mirror(region, jsontext.Value(args)); err == nil {
			t.Errorf("Mirror(%s) = %v", args, h)
		}
	}
}

// TestHR080_ParameterHeadersMustMatchTheBody: a request is accepted only
// when every present argument has its header, once, equal to it after
// decoding (integers as numbers), and no header names an absent, null or
// undeclared argument.
func TestHR080_ParameterHeadersMustMatchTheBody(t *testing.T) {
	args := jsontext.Value(`{"region":"us-west1","opts":{"limit":42},"dry":true}`)
	good := map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Limit": "42", "Mcp-Param-Dry-Run": "true"}
	with := func(change map[string]string) http.Header {
		h := http.Header{"Mcp-Method": {"tools/call"}}
		for k, v := range good {
			h.Set(k, v)
		}
		for k, v := range change {
			if v == "" {
				h.Del(k)
			} else {
				h.Set(k, v)
			}
		}
		return h
	}
	for name, change := range map[string]map[string]string{
		"as mirrored":    nil,
		"base64":         {"Mcp-Param-Region": "=?base64?dXMtd2VzdDE=?="},
		"42.0 equals 42": {"Mcp-Param-Limit": "42.0"},
	} {
		if msg := Check(with(change), region, args); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
	lower := http.Header{"mcp-param-region": {"us-west1"}, "MCP-PARAM-LIMIT": {"42"}, "Mcp-Param-Dry-Run": {"true"}}
	if msg := Check(lower, region, args); msg != "" {
		t.Errorf("header names in another case: %s", msg)
	}
	for name, change := range map[string]map[string]string{
		"missing":              {"Mcp-Param-Region": ""},
		"different":            {"Mcp-Param-Region": "us-east1"},
		"another case":         {"Mcp-Param-Region": "US-WEST1"},
		"different base64":     {"Mcp-Param-Region": "=?base64?dXMtZWFzdDE=?="},
		"broken base64":        {"Mcp-Param-Region": "=?base64?***?="},
		"raw non-ASCII":        {"Mcp-Param-Region": "us-west1" + string(rune(0xe9))},
		"another integer":      {"Mcp-Param-Limit": "43"},
		"leading zero":         {"Mcp-Param-Limit": "042"},
		"a fraction":           {"Mcp-Param-Limit": "42.5"},
		"an exponent":          {"Mcp-Param-Limit": "4.2e1"},
		"a plus sign":          {"Mcp-Param-Limit": "+42"},
		"boolean in caps":      {"Mcp-Param-Dry-Run": "True"},
		"an undeclared header": {"Mcp-Param-Query": "SELECT 1"},
	} {
		if msg := Check(with(change), region, args); msg == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	repeated := with(nil)
	repeated.Add("Mcp-Param-Region", "us-west1")
	if msg := Check(repeated, region, args); msg == "" {
		t.Error("a repeated header: accepted")
	}
	for name, body := range map[string]string{
		"absent":           `{"region":"us-west1","opts":{"limit":42}}`,
		"null":             `{"region":"us-west1","opts":{"limit":42},"dry":null}`,
		"another type":     `{"region":"us-west1","opts":{"limit":42},"dry":"true"}`,
		"an unsafe number": `{"region":"us-west1","opts":{"limit":9007199254740993},"dry":true}`,
	} {
		if msg := Check(with(nil), region, jsontext.Value(body)); msg == "" {
			t.Errorf("a header for an argument that is %s: accepted", name)
		}
	}
	if msg := Check(http.Header{}, region, jsontext.Value(`{"query":"SELECT 1","dry":null}`)); msg != "" {
		t.Errorf("no headers for absent arguments: %s", msg)
	}
	if msg := Check(http.Header{}, region, args); msg == "" {
		t.Error("no headers for present arguments: accepted")
	}
	if msg := Check(http.Header{"Mcp-Param-Region": {"us-west1"}}, nil, jsontext.Value(`{"region":"us-west1"}`)); msg == "" {
		t.Error("a header for a tool that declares none: accepted")
	}
}

// FuzzParamHeaders: no schema, arguments or header value panics; what a
// client mirrors always passes the server's check; and a forged value is
// accepted only when it decodes to the argument's own value.
func FuzzParamHeaders(f *testing.F) {
	f.Add(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`, `{"region":"us-west1"}`, "us-east1")
	f.Add(`{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"N"}}}`, `{"n":42}`, "42.00")
	f.Add(`{"type":"object","properties":{"b":{"type":"boolean","x-mcp-header":"B"}}}`, `{"b":false}`, "=?base64?ZmFsc2U=?=")
	f.Add(`{"type":"object","properties":{"o":{"type":"object","properties":{"s":{"type":"string","x-mcp-header":"S"}}}}}`,
		`{"o":{"s":" x "}}`, "=?base64?IHgg?=")
	f.Fuzz(func(t *testing.T, schema, args, value string) {
		params, err := Parse(jsontext.Value(schema))
		if err != nil || !jsontext.Value(args).IsValid() {
			return
		}
		h, err := Mirror(params, jsontext.Value(args))
		if err != nil {
			return
		}
		if msg := Check(h, params, jsontext.Value(args)); msg != "" {
			t.Fatalf("the mirrored headers %v were refused: %s", h, msg)
		}
		if len(params) == 0 {
			return
		}
		p := params[0]
		h.Set(p.Header(), value)
		if Check(h, params, jsontext.Value(args)) != "" {
			return
		}
		v, present := lookup(object(jsontext.Value(args)), p.Path)
		got, ok := Decode(value)
		want, typed := text(p.Type, v)
		if !present || !ok || !typed || !equal(p.Type, got, want) {
			t.Fatalf("accepted %s: %q for the argument %s", p.Header(), value, v)
		}
	})
}
