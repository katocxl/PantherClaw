// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// withUpstream makes the connection a kind-mcp connection to a simulated
// MCP server with faults f, and the package dispatch refunds to its tools,
// pinned to the digests of the definitions it lists.
func withUpstream(t *testing.T, f mcpsim.Faults) (*mcpsim.Server, func(*harness)) {
	t.Helper()
	sim := mcpsim.New(f)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	tools := mcpsim.New(mcpsim.Faults{}).Tools()
	create, err := upstream.ToolDigest(tools[0])
	if err != nil {
		t.Fatal(err)
	}
	get, err := upstream.ToolDigest(tools[1])
	if err != nil {
		t.Fatal(err)
	}
	return sim, func(h *harness) {
		h.conn.Kind, h.targetURL = "mcp", ts.URL+"/mcp"
		h.mutatePkg = func(raw []byte) []byte {
			for _, r := range [][2]string{
				{
					"    dispatch:\n      http:\n        method: POST\n        path: /v1/refunds\n        body:\n",
					"    dispatch:\n      mcp:\n        tool: create_refund\n        upstream_digest: " + create + "\n        arguments:\n",
				},
				{"        idempotency_header: Idempotency-Key\n", ""},
				{
					"    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n",
					"    dispatch:\n      mcp:\n        tool: get_refund\n        upstream_digest: " + get + "\n        arguments:\n          refund: target.id\n",
				},
			} {
				if bytes.Count(raw, []byte(r[0])) != 1 {
					t.Fatalf("mock payments package: %q not found once", r[0])
				}
				raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
			}
			return raw
		}
	}
}

// TestPN015_UpstreamToolCallsGoDownTheDispatchPath: a tools/call on a
// kind-mcp connection is authorized, committed with BeginDispatch binding
// the canonical {name, arguments}, sent to the upstream server's reviewed
// tool once, and recorded ACCEPTED; the agent gets the upstream content
// with PantherClaw's facts, in either protocol version.
func TestPN015_UpstreamToolCallsGoDownTheDispatchPath(t *testing.T) {
	for name, f := range map[string]mcpsim.Faults{"2026-07-28": {}, "2025-11-25 streamed": {Legacy: true, Stream: true}} {
		sim, opt := withUpstream(t, f)
		h := setup(t, opt)
		r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
		res := r.body.Result
		if r.code != http.StatusOK || res.IsError || len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, `"re_`) ||
			!strings.Contains(string(res.StructuredContent), `"status":"succeeded"`) || sim.Calls() != 1 {
			t.Fatalf("%s: tools/call = %d %+v %+v, %d upstream runs", name, r.code, r.body.Error, res, sim.Calls())
		}
		params, _ := upstream.Params("create_refund", jsontext.Value(`{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`))
		sum := sha256.Sum256(params)
		s := h.auth.snap()
		if len(s.begins) != 1 || s.begins[0].GetOutboundMethod() != http.MethodPost || s.begins[0].GetOutboundUrl() != h.targetURL ||
			!bytes.Equal(s.begins[0].GetOutboundBodySha256(), sum[:]) {
			t.Fatalf("%s: BeginDispatch %+v", name, s.begins)
		}
		if s.outcome() != pb.Outcome_OUTCOME_ACCEPTED || len(s.records[0].GetResponseDigest()) != 32 ||
			!strings.Contains(string(res.Meta["io.pantherclaw/result"]), s.txn) {
			t.Fatalf("%s: recorded %+v", name, s.records)
		}
	}
}

// TestHR082_UpstreamServersCannotAskTheAgent: a 2025-11-25 server asking
// for an elicitation, a sampling or the roots during a call gets a decline
// and "method not found", and the call completes; a 2026-07-28
// input_required result becomes a tool error the agent sees, recorded
// FAILED; a tool error is FAILED too.
func TestHR082_UpstreamServersCannotAskTheAgent(t *testing.T) {
	ask := []string{"elicitation/create", "sampling/createMessage", "roots/list"}
	sim, opt := withUpstream(t, mcpsim.Faults{Legacy: true, Ask: ask})
	h := setup(t, opt)
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil); r.body.Result.IsError ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("call with server requests = %+v", r.body.Result)
	}
	want := []string{"elicitation/create: decline", "sampling/createMessage: error -32601", "roots/list: error -32601"}
	if got := sim.Answers(); !slices.Equal(got, want) {
		t.Fatalf("answers %q, want %q", got, want)
	}
	for f, code := range map[*mcpsim.Faults]string{{InputRequired: true}: "upstream_input_required", {ToolError: true}: "tool_error"} {
		sim, opt := withUpstream(t, *f)
		h := setup(t, opt)
		r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
		if !r.body.Result.IsError || !strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), `"`+code+`"`) ||
			!strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), "tool_failed") ||
			h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
			t.Fatalf("%s: %+v, outcome %s", code, r.body.Result, h.auth.snap().outcome())
		}
		if code == "upstream_input_required" && sim.Calls() != 0 {
			t.Fatal("a tool ran after input_required")
		}
	}
}

// TestHR061_UpstreamRequestsCarryTheCredential: every request to an
// upstream MCP server carries the opened credential, which the agent never
// sees; an unreachable server fails before anything was sent.
func TestHR061_UpstreamRequestsCarryTheCredential(t *testing.T) {
	sim, opt := withUpstream(t, mcpsim.Faults{Legacy: true, Token: testSecret})
	h := setup(t, opt, withCredential(t, []string{"127.0.0.1"}))
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
	if r.body.Result.IsError || sim.Calls() != 1 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("with the credential = %+v", r.body.Result)
	}
	_, opt = withUpstream(t, mcpsim.Faults{})
	h = setup(t, opt, func(h *harness) { h.targetURL = deadURL(t) + "/mcp" })
	r = h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil)
	if !strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), "target_unreachable") ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("unreachable = %+v, outcome %s", r.body.Result, h.auth.snap().outcome())
	}
}
