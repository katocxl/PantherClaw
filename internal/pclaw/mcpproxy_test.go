// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
)

// fakeMCP is a gateway MCP endpoint that records what reaches it. It
// speaks 2026-07-28 statelessly and 2025-11-25 with sessions, which end()
// ends.
type fakeMCP struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	sessions map[string]bool
	next     int
}

func newFakeMCP(t *testing.T) *fakeMCP {
	t.Helper()
	f := &fakeMCP{sessions: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal(b, &m)
		f.mu.Lock()
		f.requests, f.bodies = append(f.requests, r), append(f.bodies, string(b))
		sid := r.Header.Get("Mcp-Session-Id")
		known := f.sessions[sid]
		if m.Method == "initialize" {
			f.next++
			sid, known = "s"+strconv.Itoa(f.next), true
			f.sessions[sid] = true
			w.Header().Set("Mcp-Session-Id", sid)
		}
		f.mu.Unlock()
		switch {
		case r.URL.Path != "/mcp/payments":
			w.WriteHeader(http.StatusNotFound)
		case sid != "" && !known:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Session not found"}}`)
		case m.ID == nil:
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "tools/call":
			// An event stream with a notification before the answer.
			w.Header().Set("Content-Type", "text/event-stream")
			id, _ := json.Marshal(m.ID)
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"+
				"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"+string(id)+",\"result\":{\"content\":[],\"isError\":false}}\n\n")
		default:
			w.Header().Set("Content-Type", "application/json")
			res := map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"method": m.Method, "protocolVersion": "2025-11-25"}}
			b, _ := json.Marshal(res, json.Deterministic(true))
			// Pretty-printed, as a server may: the proxy writes one line.
			_, _ = w.Write(bytes.ReplaceAll(b, []byte(","), []byte(",\n  ")))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeMCP) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.sessions)
}

func (f *fakeMCP) seen() ([]*http.Request, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.requests...), append([]string(nil), f.bodies...)
}

// proxyFiles writes an enrolled key file with a run and a token file.
func proxyFiles(t *testing.T) (keyFile, tokenFile, run string) {
	t.Helper()
	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	run = ids.NewV7().String()
	kf.Identifier, kf.Server, kf.RunID = "pc:org/"+ids.NewV7().String()+"/agent/"+ids.NewV7().String()+"/inst/"+ids.NewV7().String(),
		"https://pc.example.test", run
	keyFile, tokenFile = filepath.Join(dir, "key.json"), filepath.Join(dir, "token")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, tokenFile, run
}

// proxyRun runs the proxy for gateway with stdin lines and returns its
// stdout lines and stderr.
func proxyRun(t *testing.T, gateway string, lines ...string) ([]string, string) {
	t.Helper()
	keyFile, tokenFile, _ := proxyFiles(t)
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{
		"mcp", "proxy", "--gateway", gateway, "--connection", "payments", "--key-file", keyFile,
		"--token-file", tokenFile,
	}, &out, &errb, envOf(nil), Options{Stdin: strings.NewReader(strings.Join(lines, "\n") + "\n")})
	if code != 0 {
		t.Fatalf("mcp proxy = %d: %s", code, errb.String())
	}
	return strings.Split(strings.TrimSpace(out.String()), "\n"), errb.String()
}

const (
	modernCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Hello, 世界","arguments":{},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	legacyInit = `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},` +
		`"clientInfo":{"name":"desktop","version":"1"}}}`
	legacyInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	legacyList        = `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`
)

// TestHR092_MCPProxyForwardsStdioToTheGateway: each line from the client
// reaches the gateway byte for byte, signed with PAP/1 in the run, with the
// headers its version needs (Mcp-Name in base64 when it is not plain
// ASCII; the 2025-11-25 session once initialized); each answer comes back
// as one line, a stream's notifications included; a notification and a
// client's own answers produce nothing; a batch and garbage are refused
// locally.
func TestHR092_MCPProxyForwardsStdioToTheGateway(t *testing.T) {
	f := newFakeMCP(t)
	out, errs := proxyRun(t, f.URL, modernCall, legacyInit, legacyInitialized, legacyList,
		`{"jsonrpc":"2.0","id":"srv-1","result":{}}`, `[`+legacyList+`]`, `not json`)
	reqs, bodies := f.seen()
	if len(reqs) != 4 {
		t.Fatalf("%d requests reached the gateway: %q", len(reqs), bodies)
	}
	for i, want := range []string{modernCall, legacyInit, legacyInitialized, legacyList} {
		r := reqs[i]
		if bodies[i] != want || r.Header.Get("PAP-Proof") == "" || r.Header.Get("Authorization") != "PAP tok-1" || r.Header.Get("PAP-Run-Id") == "" {
			t.Errorf("request %d: %q %v", i, bodies[i], r.Header)
		}
	}
	if h := reqs[0].Header; h.Get("MCP-Protocol-Version") != "2026-07-28" || h.Get("Mcp-Method") != "tools/call" ||
		h.Get("Mcp-Name") != "=?base64?SGVsbG8sIOS4lueVjA==?=" {
		t.Errorf("2026-07-28 headers %v", h)
	}
	if h := reqs[1].Header; h.Get("MCP-Protocol-Version") != "" || h.Get("Mcp-Session-Id") != "" {
		t.Errorf("initialize headers %v", h)
	}
	for _, r := range reqs[2:] {
		if r.Header.Get("MCP-Protocol-Version") != "2025-11-25" || r.Header.Get("Mcp-Session-Id") != "s1" {
			t.Errorf("in-session headers %v", r.Header)
		}
	}
	want := []string{
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}`,
		`"id":2`, `"id":3`, `"code":-32600`, `"code":-32700`,
	}
	if len(out) != len(want) {
		t.Fatalf("stdout %q (stderr %s)", out, errs)
	}
	for i, w := range want {
		if !strings.Contains(out[i], w) || strings.Contains(out[i], "\n") {
			t.Errorf("line %d = %q, want %q", i, out[i], w)
		}
	}
}

// TestHR092_MCPProxyRenewsAnEndedSession: when the gateway ended the
// 2025-11-25 session, the proxy replays the client's initialize, announces
// it, and sends the request again in the new session.
func TestHR092_MCPProxyRenewsAnEndedSession(t *testing.T) {
	f := newFakeMCP(t)
	keyFile, tokenFile, _ := proxyFiles(t)
	r, w := io.Pipe()
	var out, errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), []string{
			"mcp", "proxy", "--gateway", f.URL, "--connection", "payments", "--key-file", keyFile,
			"--token-file", tokenFile,
		}, &out, &errb, envOf(nil), Options{Stdin: r})
	}()
	for _, l := range []string{legacyInit, legacyInitialized, legacyList} {
		_, _ = io.WriteString(w, l+"\n")
	}
	waitFor(t, func() bool { reqs, _ := f.seen(); return len(reqs) == 3 })
	f.end()
	_, _ = io.WriteString(w, legacyList+"\n")
	_ = w.Close()
	if code := <-done; code != 0 {
		t.Fatalf("mcp proxy = %d: %s", code, errb.String())
	}
	reqs, bodies := f.seen()
	if len(reqs) != 7 || bodies[4] != legacyInit || bodies[5] != legacyInitialized || reqs[6].Header.Get("Mcp-Session-Id") != "s2" {
		t.Fatalf("after the session ended: %q", bodies)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 3 || !strings.Contains(lines[2], `"id":3`) {
		t.Fatalf("stdout %q", lines)
	}
}

// TestHR092_MCPProxyReportsAnUnreachableGateway: a request gets a JSON-RPC
// error with its id; a notification gets nothing.
func TestHR092_MCPProxyReportsAnUnreachableGateway(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	_ = ln.Close()
	out, _ := proxyRun(t, dead, legacyInit, legacyInitialized)
	if len(out) != 1 || !strings.Contains(out[0], `"id":2`) || !strings.Contains(out[0], `"code":-32603`) {
		t.Fatalf("stdout %q", out)
	}
}

// TestHR092_MCPProxySpeaksOnlyStdio: the proxy's code opens no listener
// and serves nothing; it is a client of the gateway only.
func TestHR092_MCPProxySpeaksOnlyStdio(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "mcpproxy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Listening methods on any value, and server types of the standard
	// library.
	methods := map[string]bool{
		"Listen": true, "ListenPacket": true, "ListenTCP": true, "ListenUDP": true, "ListenUnix": true,
		"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true, "ServeTLS": true,
	}
	qualified := map[string]bool{"net.ListenConfig": true, "http.Server": true, "httptest.NewServer": true}
	ast.Inspect(file, func(n ast.Node) bool {
		s, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := s.Sel.Name
		if x, ok := s.X.(*ast.Ident); ok {
			name = x.Name + "." + s.Sel.Name
		}
		if methods[s.Sel.Name] || qualified[name] {
			t.Errorf("mcpproxy.go uses %s", name)
		}
		return true
	})
	for _, imp := range file.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); p == "net" || strings.HasPrefix(p, "net/http/httptest") {
			t.Errorf("mcpproxy.go imports %s", p)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeParamGateway is a 2026-07-28 gateway endpoint whose create_refund
// declares the currency for Mcp-Param-Currency, and which refuses a call
// whose headers do not match its body (HeaderMismatch), as the gateway
// does.
func fakeParamGateway(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	declared := []mcpheader.Param{{Name: "Currency", Path: []string{"currency"}, Type: "string"}}
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			ID     jsontext.Value `json:"id"`
			Method string         `json:"method"`
			Params struct {
				Arguments jsontext.Value `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		seen = append(seen, m.Method+" "+r.Header.Get("Mcp-Param-Currency"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch m.Method {
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"resultType":"complete","tools":[{"name":"create_refund",`+
				`"description":"Refund","inputSchema":{"type":"object","properties":{"currency":{"type":"string","x-mcp-header":"Currency"}}}}]}}`)
		case "tools/call":
			if msg := mcpheader.Check(r.Header, declared, m.Params.Arguments); msg != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32020,"message":"Header mismatch"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"content":[],"isError":false}}`)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TestHR080_MCPProxyMirrorsDeclaredParameters: a 2026-07-28 call carries
// the Mcp-Param-* headers the tool's served schema declares, learned from
// a tool list the client asked for; a call the gateway refuses for its
// headers makes the proxy list the tools itself and send it once more;
// a call that still does not match gets the gateway's error.
func TestHR080_MCPProxyMirrorsDeclaredParameters(t *testing.T) {
	const (
		meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
		list = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`
		call = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_refund","arguments":{"currency":"USD"},` + meta + `}}`
		odd  = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_refund","arguments":{"currency":840},` + meta + `}}`
	)
	ts, seen := fakeParamGateway(t)
	out, _ := proxyRun(t, ts.URL, list, call)
	if got := seen(); strings.Join(got, ",") != "tools/list ,tools/call USD" || len(out) != 2 || !strings.Contains(out[1], `"isError":false`) {
		t.Fatalf("after a tool list: gateway saw %q, stdout %q", got, out)
	}

	ts, seen = fakeParamGateway(t)
	out, _ = proxyRun(t, ts.URL, call, odd)
	if got := seen(); strings.Join(got, ",") != "tools/call ,tools/list ,tools/call USD,tools/call ,tools/list ,tools/call " {
		t.Fatalf("without a tool list: gateway saw %q", got)
	}
	if len(out) != 2 || !strings.Contains(out[0], `"isError":false`) || !strings.Contains(out[1], `"code":-32020`) || !strings.Contains(out[1], `"id":3`) {
		t.Fatalf("stdout %q", out)
	}
}
