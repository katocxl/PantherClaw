// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

var update = flag.Bool("update", false, "rewrite golden files")

var tc = Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func mockRaw(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mapperFor(t testing.TB, raw []byte) *Mapper {
	t.Helper()
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const refundArgs = `{"charge":"ch_1","amount":"30","currency":"USD","reason":"duplicate"}`

// TestHR124_MockPaymentsMappingGolden pins the ActionIR the reviewed
// mappings produce for fixed calls: a mapping change is visible here.
func TestHR124_MockPaymentsMappingGolden(t *testing.T) {
	m := mapperFor(t, mockRaw(t))
	ctx := context.Background()
	var out bytes.Buffer
	for _, c := range []struct {
		name string
		run  func() (actionir.Parsed, error)
	}{
		{"mcp create_refund", func() (actionir.Parsed, error) { return m.MCP(ctx, tc, "create_refund", []byte(refundArgs)) }},
		{"http POST /v1/refunds", func() (actionir.Parsed, error) { return m.HTTP(ctx, tc, "POST", "/v1/refunds", "", []byte(refundArgs)) }},
		{"mcp get_refund", func() (actionir.Parsed, error) { return m.MCP(ctx, tc, "get_refund", []byte(`{"refund":"re_1"}`)) }},
		{"http GET /v1/refunds/re_1", func() (actionir.Parsed, error) { return m.HTTP(ctx, tc, "GET", "/v1/refunds/re_1", "", nil) }},
	} {
		p, err := c.run()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fmt.Fprintf(&out, "%s %s\n%s\n", c.name, p.HashHex(), p.Canonical)
	}
	path := filepath.Join("testdata", "mock-payments.actionir")
	if *update {
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("mapping output changed; a mapping change must be deliberate (HR-124).\n got:\n%s\nwant:\n%s", out.Bytes(), want)
	}
}

// TestF099_SameEffectSameMeaningOnEveryChannel: MCP and HTTP calls for one
// effect produce the same operation, target, params, dedupe key and pinned
// definition.
func TestF099_SameEffectSameMeaningOnEveryChannel(t *testing.T) {
	m := mapperFor(t, mockRaw(t))
	a, err := m.MCP(context.Background(), tc, "create_refund", []byte(refundArgs))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.HTTP(context.Background(), tc, "POST", "/v1/refunds", "", []byte(refundArgs))
	if err != nil {
		t.Fatal(err)
	}
	x, y := a.Action, b.Action
	if x.Operation != y.Operation || x.Target != y.Target || !bytes.Equal(x.Params, y.Params) ||
		x.DedupeKey != y.DedupeKey || x.Definition != y.Definition || x.DedupeKey == "" {
		t.Fatalf("channels disagree:\n%s\n%s", a.Canonical, b.Canonical)
	}
	if x.Channel != "mcp" || y.Channel != "http" {
		t.Fatal("the channel is recorded")
	}
}

func refund(t *testing.T, args string) (actionir.Parsed, error) {
	t.Helper()
	return mapperFor(t, mockRaw(t)).MCP(context.Background(), tc, "create_refund", []byte(args))
}

func TestHR101_NumberAmountsNeverBecomeMoney(t *testing.T) {
	canonical, err := refund(t, refundArgs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical.Canonical), `"amount":{"currency":"USD","value":"30.00"}`) {
		t.Fatalf("amount not canonical: %s", canonical.Canonical)
	}
	// "30" and "30.00" are one amount: same ActionIR, same dedupe key.
	same, err := refund(t, strings.Replace(refundArgs, `"30"`, `"30.00"`, 1))
	if err != nil || same.Hash != canonical.Hash {
		t.Fatalf("reformatted amount changed the action: %v", err)
	}
	for name, amount := range map[string]string{
		"JSON integer":  `30`,
		"JSON fraction": `30.5`,
		"exponent":      `"3e1"`,
		"too precise":   `"30.001"`,
		"negative":      `"-30.00"`,
		"zero":          `"0"`,
		"over the max":  `"1000000.01"`,
	} {
		_, err := refund(t, strings.Replace(refundArgs, `"30"`, amount, 1))
		if !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous", name, err)
		}
	}
}

func TestHR100_MappingInputIsStrict(t *testing.T) {
	for name, args := range map[string]string{
		"duplicate key":   `{"charge":"ch_1","charge":"ch_2","amount":"30","currency":"USD","reason":"duplicate"}`,
		"invalid UTF-8":   "{\"charge\":\"ch_\xff\",\"amount\":\"30\",\"currency\":\"USD\",\"reason\":\"duplicate\"}",
		"unmapped field":  `{"charge":"ch_1","amount":"30","currency":"USD","reason":"duplicate","metadata":{}}`,
		"trailing data":   refundArgs + `{}`,
		"not an object":   `["ch_1"]`,
		"too deep":        `{"charge":"ch_1","x":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}`,
		"number too big":  `{"charge":"ch_1","x":99999999999999999999}`,
		"null amount":     `{"charge":"ch_1","amount":null,"currency":"USD","reason":"duplicate"}`,
		"wrong type":      `{"charge":["ch_1"],"amount":"30","currency":"USD","reason":"duplicate"}`,
		"reason a number": `{"charge":"ch_1","amount":"30","currency":"USD","reason":1}`,
	} {
		if _, err := refund(t, args); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous", name, err)
		}
	}
	m := mapperFor(t, mockRaw(t))
	for name, q := range map[string]string{"repeated": "x=1&x=2", "unread": "expand=true", "semicolon": "a=1;b=2"} {
		if _, err := m.HTTP(context.Background(), tc, "GET", "/v1/refunds/re_1", q, nil); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("query %s: err = %v, want ErrAmbiguous", name, err)
		}
	}
}

func TestHR102_TargetsRejectConfusables(t *testing.T) {
	for name, charge := range map[string]string{
		"cyrillic":  "ch_" + string(rune(0x0430)),
		"bidi":      "ch_1" + string(rune(0x202e)),
		"space":     "ch_1 ",
		"wrong id":  "ch-1",
		"too long":  "ch_" + strings.Repeat("a", 65),
		"other obj": "re_1",
	} {
		args := strings.Replace(refundArgs, `"ch_1"`, `"`+charge+`"`, 1)
		if _, err := refund(t, args); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous", name, err)
		}
	}
}

func TestHR103_MissingOrUnmappedCallsAreNeverDefaulted(t *testing.T) {
	for name, args := range map[string]string{
		"no charge":   `{"amount":"30","currency":"USD","reason":"duplicate"}`,
		"no reason":   `{"charge":"ch_1","amount":"30","currency":"USD"}`,
		"no currency": `{"charge":"ch_1","amount":"30","reason":"duplicate"}`,
		"bad reason":  `{"charge":"ch_1","amount":"30","currency":"USD","reason":"goodwill"}`,
		"bad money":   `{"charge":"ch_1","amount":"30","currency":"GBP","reason":"duplicate"}`,
		"empty":       ``,
	} {
		if _, err := refund(t, args); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous", name, err)
		}
	}
	m := mapperFor(t, mockRaw(t))
	ctx := context.Background()
	if _, err := m.MCP(ctx, tc, "delete_everything", []byte(`{}`)); !errors.Is(err, ErrUnmapped) {
		t.Errorf("unknown tool: %v", err)
	}
	for _, c := range [][2]string{
		{"GET", "/v1/refunds"},
		{"DELETE", "/v1/refunds/re_1"},
		{"GET", "/v1/refunds/re_1/"},
		{"GET", "/v1/refunds/re%5F1"},
		{"GET", "/v1/refunds/.."},
		{"GET", "/v1//refunds"},
		{"GET", "v1/refunds/re_1"},
		{"get", "/v1/refunds/re_1"},
		{"GET", "/V1/refunds/re_1"},
	} {
		if _, err := m.HTTP(ctx, tc, c[0], c[1], "", nil); !errors.Is(err, ErrUnmapped) {
			t.Errorf("%s %s: err = %v, want ErrUnmapped", c[0], c[1], err)
		}
		if r, ok := m.HTTPRoute(c[0], c[1]); ok {
			t.Errorf("%s %s: route %q", c[0], c[1], r)
		}
	}
	if r, ok := m.HTTPRoute("GET", "/v1/refunds/re_1"); !ok || r != "payments-refund-get" {
		t.Errorf("route of GET /v1/refunds/re_1: %q %v", r, ok)
	}
}

func TestPackageLoadRejectsUnsafeMappings(t *testing.T) {
	for name, edit := range map[string][2]string{
		"wrong type":         {"reason: input.reason", "reason: size(input.reason)"},
		"float":              {"reason: input.reason", `reason: string(1.5)`},
		"whole input":        {"target_id: input.charge", "target_id: string(input)"},
		"input passed whole": {"target_id: input.charge", `target_id: 'size(input) > 0 ? input.charge : "ch_x"'`},
		"iterating input":    {"reason: input.reason", `reason: 'input.exists(k, k == "x") ? "duplicate" : "fraudulent"'`},
		"undeclared path":    {"target_id: path.refund", "target_id: path.nope"},
		"unsafe ordering":    {"reason: input.reason", `reason: 'input.reason > "a" ? "duplicate" : "fraudulent"'`},
		"does not parse":     {"reason: input.reason", "reason: input.reason +"},
		"string amount math": {"amount: money(input.amount, input.currency)", "amount: input.amount"},
	} {
		raw := bytes.ReplaceAll(mockRaw(t), []byte(edit[0]), []byte(edit[1]))
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = New(p, celenv.DefaultLimits)
		if name == "string amount math" {
			// dyn is accepted at load; the runtime type check rejects it.
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			m, _ := New(p, celenv.DefaultLimits)
			if _, err := m.MCP(context.Background(), tc, "create_refund", []byte(refundArgs)); !errors.Is(err, actionir.ErrAmbiguous) {
				t.Errorf("%s: a string where money is declared: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		t.Logf("%s: %v", name, err)
	}
}

// FuzzCanonicalMapping checks that any call the mapping accepts yields a
// valid, canonical, deterministic ActionIR, identical in meaning on every
// channel.
func FuzzCanonicalMapping(f *testing.F) {
	m := mapperFor(f, mockRaw(f))
	f.Add([]byte(refundArgs))
	f.Add([]byte(`{"charge":"ch_x","amount":"0.01","currency":"EUR","reason":"fraudulent"}`))
	f.Add([]byte(`{"charge":"ch_1","amount":30,"currency":"USD","reason":"duplicate"}`))
	f.Fuzz(func(t *testing.T, args []byte) {
		ctx := context.Background()
		a, err := m.MCP(ctx, tc, "create_refund", args)
		if err != nil {
			if !errors.Is(err, actionir.ErrAmbiguous) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		re, err := actionir.Parse(a.Canonical)
		if err != nil || re.Hash != a.Hash || !bytes.Equal(re.Canonical, a.Canonical) {
			t.Fatalf("canonical ActionIR does not round-trip: %v\n%s", err, a.Canonical)
		}
		again, err := m.MCP(ctx, tc, "create_refund", args)
		if err != nil || again.Hash != a.Hash {
			t.Fatalf("mapping is not deterministic: %v", err)
		}
		b, err := m.HTTP(ctx, tc, "POST", "/v1/refunds", "", args)
		if err != nil || !bytes.Equal(b.Action.Params, a.Action.Params) || b.Action.DedupeKey != a.Action.DedupeKey {
			t.Fatalf("channels disagree: %v", err)
		}
	})
}
