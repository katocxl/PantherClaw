// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
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
				Name        string            `json:"name"`
				Title       string            `json:"title"`
				Description string            `json:"description"`
				InputSchema jsontext.Value    `json:"inputSchema"`
				Execution   map[string]string `json:"execution"`
			} `json:"tools"`
			// 2025-11-25: initialize, CreateTaskResult and Task.
			ProtocolVersion string `json:"protocolVersion"`
			Task            *struct {
				TaskID       string `json:"taskId"`
				Status       string `json:"status"`
				TTL          int    `json:"ttl"`
				PollInterval int    `json:"pollInterval"`
			} `json:"task"`
			TTL               int            `json:"ttl"`
			SupportedVersions []string       `json:"supportedVersions"`
			Capabilities      jsontext.Value `json:"capabilities"`
			TaskID            string         `json:"taskId"`
			Status            string         `json:"status"`
			PollIntervalMs    int            `json:"pollIntervalMs"`
			Result            *struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				Meta map[string]jsontext.Value `json:"_meta"`
			} `json:"result"`
			CacheScope string                    `json:"cacheScope"`
			TTLMs      int                       `json:"ttlMs"`
			Meta       map[string]jsontext.Value `json:"_meta"`
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
			Name   string `json:"name"`
			TaskID string `json:"taskId"`
		} `json:"params"`
	}
	_ = json.Unmarshal([]byte(body), &probe)
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", probe.Method)
	if n := probe.Params.Name + probe.Params.TaskID; n != "" {
		req.Header.Set("Mcp-Name", n)
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

// withTasks declares the tasks extension in a body from jsonRPC.
func withTasks(body string) string {
	return strings.Replace(body, `"io.modelcontextprotocol/clientCapabilities":{}`,
		`"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}`, 1)
}

func taskBody(method, id string) string {
	return withTasks(jsonRPC(method, `"taskId":"`+id+`"`))
}

func (f *fakeAuthority) decide(d pb.Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decision = d
}

func (f *fakeAuthority) setIdentity(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity = code
}

// TestHR185_AnIdenticalHeldCallReusesTheHeldAction: while a call is held,
// the same call by the same run and instance carries the held action id,
// so an approval binds to it. A changed argument, another run or another
// instance is a new action; once the action is decided, the next call is
// new; a client's own action id is kept.
func TestHR185_AnIdenticalHeldCallReusesTheHeldAction(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL })
	run := ids.NewV7().String()
	call := func(args string, hdr map[string]string) string {
		t.Helper()
		before := len(h.auth.snap().actions)
		if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", args), hdr); r.code != http.StatusOK {
			t.Fatalf("tools/call = %d %+v", r.code, r.body.Error)
		}
		acts := h.auth.snap().actions
		if len(acts) != before+1 {
			t.Fatalf("%d actions reached the Authority", len(acts)-before)
		}
		return acts[len(acts)-1].Action.ActionID
	}
	same := map[string]string{HeaderRunID: run}
	held := call(refundArgs, same)
	if id := call(refundArgs, same); id != held {
		t.Fatalf("identical call: %s, held %s", id, held)
	}
	for name, tc := range map[string]struct {
		args string
		hdr  map[string]string
	}{
		"changed argument": {strings.Replace(refundArgs, `"30.00"`, `"31.00"`, 1), same},
		"another run":      {refundArgs, map[string]string{HeaderRunID: ids.NewV7().String()}},
		"another instance": {refundArgs, map[string]string{HeaderRunID: run, "Authorization": "PAP " + workloadTokenFor(ids.NewV7().String())}},
	} {
		if id := call(tc.args, tc.hdr); id == held {
			t.Errorf("%s reused the held action", name)
		}
	}
	h.auth.decide(pb.Decision_DECISION_ALLOW)
	if id := call(refundArgs, same); id != held || h.target.calls() != 1 {
		t.Fatalf("approved call: %s (held %s), target %d", id, held, h.target.calls())
	}
	h.auth.decide(pb.Decision_DECISION_REQUIRE_APPROVAL)
	if id := call(refundArgs, same); id == held {
		t.Fatal("a decided action was reused")
	}
	own := ids.NewV7().String()
	if id := call(refundArgs, map[string]string{HeaderRunID: run, HeaderActionID: own}); id != own {
		t.Fatalf("the client's action id %s became %s", own, id)
	}
}

// TestHR185_HeldCallsBecomeTasksOfTheirBinding: a client that declares
// the tasks extension gets a task for a held call. Requests from another
// run or instance get "task not found" and resubmit nothing. A poll from
// the creating binding resubmits the same action with its own credentials;
// once allowed, the call runs and the task completes with the tool's
// result, which later polls read without deciding again.
func TestHR185_HeldCallsBecomeTasksOfTheirBinding(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL })
	same := map[string]string{HeaderRunID: ids.NewV7().String()}
	r := h.mcpCall(t, http.MethodPost, mcpPath, withTasks(jsonRPC("tools/call", refundArgs)), same)
	res := r.body.Result
	if r.code != http.StatusOK || res.ResultType != "task" || res.Status != "working" || len(res.TaskID) != 43 ||
		res.PollIntervalMs != 5000 || res.Meta["io.pantherclaw/hold"] == nil || h.target.calls() != 0 {
		t.Fatalf("held call = %d %+v %+v", r.code, r.body.Error, res)
	}
	id, held := res.TaskID, h.auth.snap().actions[0].Action.ActionID
	before := h.auth.snap().authorize
	for name, hdr := range map[string]map[string]string{
		"run":      {HeaderRunID: ids.NewV7().String()},
		"instance": {HeaderRunID: same[HeaderRunID], "Authorization": "PAP " + workloadTokenFor(ids.NewV7().String())},
	} {
		for _, m := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
			if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody(m, id), hdr); r.code != http.StatusOK || r.errCode() != -32602 {
				t.Errorf("%s from another %s: %d %+v %+v", m, name, r.code, r.body.Error, r.body.Result)
			}
		}
	}
	if h.auth.snap().authorize != before {
		t.Fatal("another binding resubmitted the action")
	}
	get := taskBody("tasks/get", id)
	r = h.mcpCall(t, http.MethodPost, mcpPath, get, same)
	s := h.auth.snap()
	sum := sha256.Sum256([]byte(get))
	if r.body.Result.ResultType != "complete" || r.body.Result.Status != "working" || s.authorize != before+1 ||
		s.actions[len(s.actions)-1].Action.ActionID != held || !bytes.Equal(s.creds.GetBodySha256(), sum[:]) {
		t.Fatalf("held poll = %+v, authorize %d", r.body.Result, s.authorize)
	}
	h.auth.decide(pb.Decision_DECISION_ALLOW)
	r = h.mcpCall(t, http.MethodPost, mcpPath, get, same)
	if res := r.body.Result; res.Status != "completed" || res.Result == nil || res.Result.IsError || len(res.Result.Content) != 1 ||
		!strings.Contains(res.Result.Content[0].Text, `"re_1"`) || h.target.calls() != 1 {
		t.Fatalf("allowed poll = %+v, target %d", res, h.target.calls())
	}
	n := h.auth.snap().authorize
	if r := h.mcpCall(t, http.MethodPost, mcpPath, get, same); r.body.Result.Status != "completed" || h.auth.snap().authorize != n ||
		h.target.calls() != 1 {
		t.Fatalf("completed poll = %+v, authorize %d", r.body.Result, h.auth.snap().authorize-n)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/cancel", id), same); r.code != http.StatusOK ||
		r.body.Result.ResultType != "complete" {
		t.Fatalf("cancel = %d %+v", r.code, r.body.Error)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, get, same); r.errCode() != -32602 {
		t.Fatalf("poll after cancel = %+v", r.body.Result)
	}
}

// TestHR185_TaskRequestsFollowTheExtensionRules: discovery advertises the
// extension; a client without it gets the held tool error; a task request
// without it is -32021 and one whose Mcp-Name is not the task id is
// -32020, before any Authority call; an unknown task is not found; a poll
// whose workload does not verify is 401 and leaves the task to the next
// poll.
func TestHR185_TaskRequestsFollowTheExtensionRules(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL })
	r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("server/discover", ""), nil)
	if !strings.Contains(string(r.body.Result.Capabilities), `"io.modelcontextprotocol/tasks":{}`) {
		t.Fatalf("capabilities %s", r.body.Result.Capabilities)
	}
	same := map[string]string{HeaderRunID: ids.NewV7().String()}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), same); !r.body.Result.IsError ||
		r.body.Result.ResultType != "complete" {
		t.Fatalf("held call without tasks = %+v", r.body.Result)
	}
	id := h.mcpCall(t, http.MethodPost, mcpPath, withTasks(jsonRPC("tools/call", refundArgs)), same).body.Result.TaskID
	before := h.auth.snap().authorize
	h.auth.mu.Lock()
	verifies := h.auth.verifies
	h.auth.mu.Unlock()
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tasks/get", `"taskId":"`+id+`"`), same); r.code != http.StatusBadRequest ||
		r.errCode() != -32021 || !strings.Contains(string(r.body.Error.Data), "io.modelcontextprotocol/tasks") {
		t.Errorf("without the extension: %d %+v", r.code, r.body.Error)
	}
	for name, v := range map[string]string{"missing": "", "another task": "x" + id} {
		hdr := map[string]string{HeaderRunID: same[HeaderRunID], "Mcp-Name": v}
		if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/get", id), hdr); r.code != http.StatusBadRequest || r.errCode() != -32020 {
			t.Errorf("Mcp-Name %s: %d %+v", name, r.code, r.body.Error)
		}
	}
	h.auth.mu.Lock()
	reached := h.auth.authorize != before || h.auth.verifies != verifies
	h.auth.mu.Unlock()
	if reached {
		t.Fatal("a refused task request reached the Authority")
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/get", "no-such-task"), same); r.code != http.StatusOK || r.errCode() != -32602 {
		t.Errorf("unknown task: %d %+v", r.code, r.body.Error)
	}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/update", id), same); r.code != http.StatusOK || r.body.Result.ResultType != "complete" {
		t.Errorf("update: %d %+v", r.code, r.body.Error)
	}
	h.auth.setIdentity("invalid_proof")
	if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/get", id), same); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "invalid_proof" {
		t.Fatalf("unverified poll: %d %v", r.code, r.hdr)
	}
	h.auth.setIdentity("")
	n := h.auth.snap().authorize
	if r := h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/get", id), same); r.body.Result.Status != "working" || h.auth.snap().authorize != n+1 {
		t.Fatalf("poll after a refused one: %+v, authorize %d", r.body.Result, h.auth.snap().authorize-n)
	}
}
