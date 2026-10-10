// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const mcpPath = "/mcp/payments"

// jsonRPC is a JSON-RPC request body with the 2026-07-28 _meta; params are
// the method's own fields (a JSON object's members, without braces).
func jsonRPC(method, params string) string {
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	if params != "" {
		meta += "," + params
	}
	return `{"jsonrpc":"2.0","id":7,"method":"` + method + `","params":{` + meta + `}}`
}

type mcpReply struct {
	code int
	hdr  http.Header
	body struct {
		ID     jsontext.Value `json:"id"`
		Result struct {
			ResultType string `json:"resultType"`
			IsError    bool   `json:"isError"`
			Content    []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			StructuredContent jsontext.Value `json:"structuredContent"`
			Tools             []struct {
				Name        string         `json:"name"`
				Title       string         `json:"title"`
				Description string         `json:"description"`
				InputSchema jsontext.Value `json:"inputSchema"`
			} `json:"tools"`
			SupportedVersions []string                  `json:"supportedVersions"`
			CacheScope        string                    `json:"cacheScope"`
			TTLMs             int                       `json:"ttlMs"`
			Meta              map[string]jsontext.Value `json:"_meta"`
		} `json:"result"`
		Error *struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    jsontext.Value `json:"data"`
		} `json:"error"`
	}
}

// mcpCall posts body to path as the test workload. Headers default to the
// ones a conforming client sends for the body's method and name; hdr
// overrides them ("" deletes).
func (h *harness) mcpCall(t *testing.T, method, path, body string, hdr map[string]string) mcpReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+path, strings.NewReader(body))
	var probe struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal([]byte(body), &probe)
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", probe.Method)
	if probe.Params.Name != "" {
		req.Header.Set("Mcp-Name", probe.Params.Name)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	r := mcpReply{code: resp.StatusCode, hdr: resp.Header}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &r.body); err != nil {
			t.Fatalf("reply %d %q: %v", resp.StatusCode, b, err)
		}
	}
	return r
}

func (r mcpReply) errCode() int {
	if r.body.Error == nil {
		return 0
	}
	return r.body.Error.Code
}

const refundArgs = `"name":"create_refund","arguments":{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`

// TestHR080_MCPHeadersMustMatchTheBody: a missing or different
// MCP-Protocol-Version, Mcp-Method or Mcp-Name (plain or base64) is 400
// HeaderMismatch (-32020), and nothing reaches the Authority; a matching
// base64 Mcp-Name is accepted.
func TestHR080_MCPHeadersMustMatchTheBody(t *testing.T) {
	h := setup(t)
	call := jsonRPC("tools/call", refundArgs)
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	for name, tc := range map[string]struct {
		body string
		hdr  map[string]string
	}{
		"no protocol version header": {call, map[string]string{"MCP-Protocol-Version": ""}},
		"another protocol version":   {call, map[string]string{"MCP-Protocol-Version": "2025-11-25"}},
		"no Mcp-Method":              {call, map[string]string{"Mcp-Method": ""}},
		"another Mcp-Method":         {call, map[string]string{"Mcp-Method": "tools/list"}},
		"no Mcp-Name":                {call, map[string]string{"Mcp-Name": ""}},
		"another Mcp-Name":           {call, map[string]string{"Mcp-Name": "get_refund"}},
		"another base64 Mcp-Name":    {call, map[string]string{"Mcp-Name": b64("get_refund")}},
		"broken base64 Mcp-Name":     {call, map[string]string{"Mcp-Name": "=?base64?!!!?="}},
		"Mcp-Name on tools/list":     {jsonRPC("tools/list", ""), map[string]string{"Mcp-Name": "create_refund"}},
		"no _meta version": {
			`{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`, nil,
		},
	} {
		r := h.mcpCall(t, http.MethodPost, mcpPath, tc.body, tc.hdr)
		if r.code != http.StatusBadRequest || r.errCode() != -32020 {
			t.Errorf("%s: %d %+v", name, r.code, r.body.Error)
		}
	}
	if s := h.auth.snap(); s.authorize != 0 || h.auth.verifies != 0 {
		t.Fatalf("a mismatched request reached the Authority: authorize %d verify %d", s.authorize, h.auth.verifies)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, call, map[string]string{"Mcp-Name": b64("create_refund")}); r.code != http.StatusOK ||
		r.body.Result.IsError {
		t.Fatalf("base64 Mcp-Name: %d %+v %+v", r.code, r.body.Error, r.body.Result)
	}
}

// TestHR080_BatchesAndOtherShapesAreRefused: a batch, GET and DELETE, an
// unsupported version, an unknown method, a foreign Origin, an unknown
// connection and a notification each get their answer.
func TestHR080_BatchesAndOtherShapesAreRefused(t *testing.T) {
	h := setup(t)
	if r := h.mcpCall(t, http.MethodPost, mcpPath, "["+jsonRPC("tools/list", "")+"]", nil); r.code != http.StatusBadRequest || r.errCode() != -32600 {
		t.Errorf("batch: %d %+v", r.code, r.body.Error)
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		if r := h.mcpCall(t, m, mcpPath, "", nil); r.code != http.StatusMethodNotAllowed || r.hdr.Get("Allow") != http.MethodPost {
			t.Errorf("%s: %d", m, r.code)
		}
	}
	old := strings.ReplaceAll(jsonRPC("tools/list", ""), "2026-07-28", "2025-11-25")
	r := h.mcpCall(t, http.MethodPost, mcpPath, old, map[string]string{"MCP-Protocol-Version": "2025-11-25"})
	if r.code != http.StatusBadRequest || r.errCode() != -32022 || !strings.Contains(string(r.body.Error.Data), `"2026-07-28"`) {
		t.Errorf("unsupported version: %d %+v", r.code, r.body.Error)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("resources/list", ""), nil); r.code != http.StatusNotFound || r.errCode() != -32601 {
		t.Errorf("unknown method: %d %+v", r.code, r.body.Error)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/list", ""), map[string]string{"Origin": "https://evil.example"}); r.code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", r.code)
	}
	if r := h.mcpCall(t, http.MethodPost, "/mcp/other", jsonRPC("tools/list", ""), nil); r.code != http.StatusNotFound {
		t.Errorf("unknown connection: %d", r.code)
	}
	note := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if r := h.mcpCall(t, http.MethodPost, mcpPath, note, nil); r.code != http.StatusAccepted {
		t.Errorf("notification: %d", r.code)
	}
}

// TestHR081_MCPClientsSeeOnlyTheReviewedTools: tools/list returns exactly
// the connection's reviewed MCP tools, sorted, with the package's
// descriptions and schemas, private and not stored; the Authority verifies
// the workload first (HR-021), and an unverified one is refused.
func TestHR081_MCPClientsSeeOnlyTheReviewedTools(t *testing.T) {
	h := setup(t)
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/list", ""), nil)
	if r.code != http.StatusOK || r.body.Result.CacheScope != "private" || r.body.Result.TTLMs <= 0 ||
		r.hdr.Get("Cache-Control") != "private, no-store" || r.hdr.Get(HeaderNonce) != "nonce-4" {
		t.Fatalf("tools/list = %d %+v %v", r.code, r.body.Result, r.hdr)
	}
	var names []string
	for _, tl := range r.body.Result.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "create_refund,get_refund" {
		t.Fatalf("tools %v", names)
	}
	refund := r.body.Result.Tools[0]
	if !strings.Contains(refund.Description, "SIMULATED") || !strings.Contains(string(refund.InputSchema), `"additionalProperties":false`) {
		t.Fatalf("create_refund as served: %+v", refund)
	}
	if c := h.auth.snap().creds; h.auth.verifies != 1 || c.GetHtu() != "http://127.0.0.1:8090"+mcpPath || c.GetWorkloadToken() != testWorkloadToken() {
		t.Fatalf("verify %d with %+v", h.auth.verifies, c)
	}
	d := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("server/discover", ""), nil)
	if d.code != http.StatusOK || strings.Join(d.body.Result.SupportedVersions, ",") != "2026-07-28" || d.body.Result.CacheScope != "private" {
		t.Fatalf("server/discover = %d %+v", d.code, d.body.Result)
	}
	h.auth.mu.Lock()
	h.auth.identity = "proof_replay"
	h.auth.mu.Unlock()
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/list", ""), nil); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "proof_replay" || len(r.body.Result.Tools) != 0 {
		t.Fatalf("unverified workload: %d %v", r.code, r.hdr)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/list", ""), map[string]string{HeaderProof: ""}); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "use_nonce" {
		t.Fatalf("no proof: %d %v", r.code, r.hdr)
	}
}

// TestPN015_ToolsCallGoesDownTheDispatchPath: a tools/call is mapped
// through the package, authorized and dispatched like an HTTP request; the
// result carries the target's answer and PantherClaw's facts.
func TestPN015_ToolsCallGoesDownTheDispatchPath(t *testing.T) {
	h := setup(t)
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
	if r.code != http.StatusOK || r.body.Result.IsError || r.body.Result.ResultType != "complete" ||
		len(r.body.Result.Content) != 1 || !strings.Contains(r.body.Result.Content[0].Text, `"re_1"`) || len(r.body.Result.StructuredContent) == 0 {
		t.Fatalf("tools/call = %d %+v %+v", r.code, r.body.Error, r.body.Result)
	}
	if body, _ := h.target.req(0); body != outbound {
		t.Fatalf("outbound %q", body)
	}
	if !strings.Contains(string(r.body.Result.Meta["io.pantherclaw/result"]), h.auth.snap().txn) {
		t.Fatalf("result _meta %v", r.body.Result.Meta)
	}
	if a := h.auth.snap().actions[0].Action; a.Channel != "mcp" || a.Connection != connID || a.Route != "payments-refund" {
		t.Fatalf("mapped %+v", a)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", `"name":"delete_everything","arguments":{}`), nil); r.code != http.StatusOK ||
		r.errCode() != -32602 {
		t.Fatalf("unknown tool: %d %+v", r.code, r.body.Error)
	}
	extra := strings.Replace(refundArgs, `"reason":"duplicate"`, `"reason":"duplicate","to":"acct_x"`, 1)
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", extra), nil); !r.body.Result.IsError ||
		!strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), "cannot_authorize") {
		t.Fatalf("invalid arguments: %+v", r.body.Result)
	}
}

// TestF642_MCPRefusalsAreToolErrors: a denial and a hold are tool errors
// (isError) whose _meta says why, with io.pantherclaw/hold for a hold;
// nothing reaches the target.
func TestF642_MCPRefusalsAreToolErrors(t *testing.T) {
	for d, want := range map[pb.Decision]string{
		pb.Decision_DECISION_DENY:             "policy_denied",
		pb.Decision_DECISION_REQUIRE_APPROVAL: "held",
	} {
		h := setup(t, func(h *harness) { h.auth.decision = d })
		r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
		if r.code != http.StatusOK || !r.body.Result.IsError || !strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), want) ||
			h.target.calls() != 0 {
			t.Errorf("%s: %d %+v", d, r.code, r.body.Result)
		}
		_, held := r.body.Result.Meta["io.pantherclaw/hold"]
		if held != (want == "held") {
			t.Errorf("%s: hold _meta %v", d, r.body.Result.Meta)
		}
	}
}
