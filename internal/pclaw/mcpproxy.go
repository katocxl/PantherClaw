// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
)

// `pclaw mcp proxy` (G0 M6 design decision 13; HR-092) lets an
// off-the-shelf MCP client reach a gateway connection: the client starts it
// as a stdio MCP server, and it posts each message it reads to the
// gateway's MCP endpoint, signed with PAP/1 by the desktop workload's key
// in the configured run, with the MCP request headers taken from the
// message itself. A 2026-07-28 tools/call also carries the Mcp-Param-*
// headers the tool's served schema declares (x-mcp-header), learned from
// the tool lists the gateway sends; when the gateway refuses a call's
// headers (HeaderMismatch), the proxy lists the tools itself and sends the
// call once more. Answers go back one per line. It speaks only stdio and
// never opens a listener, so nothing else on the machine can use the
// workload's identity through it (HR-092). Diagnostics go to stderr; stdout
// carries only the protocol.

func init() {
	commands["mcp proxy"] = command{
		usage: "mcp proxy --gateway URL --connection NAME --key-file FILE [--run ID] [--token-file FILE]",
		run:   mcpProxy,
	}
}

const (
	// proxyMaxMessage bounds one message from the client (the gateway
	// accepts 256 KiB).
	proxyMaxMessage = 256 << 10
	// proxyMaxAnswer bounds one answer from the gateway.
	proxyMaxAnswer = 16 << 20
	// proxyTimeout bounds one request to the gateway.
	proxyTimeout = 2 * time.Minute
	// legacyVersion is the MCP revision with sessions.
	legacyVersion = "2025-11-25"
)

func mcpProxy(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("mcp proxy", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	gateway := fs.String("gateway", "", "the gateway's public URL")
	conn := fs.String("connection", "", "the connection to reach")
	keyFile := fs.String("key-file", "", "the enrolled desktop workload key file")
	runFlag := fs.String("run", "", "the run (default: the key file's)")
	tokenFile := fs.String("token-file", "", "a workload token to use instead of issuing one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *gateway == "" || *conn == "" || *keyFile == "" || fs.NArg() != 0 {
		return errUsage
	}
	base, err := checkServer(*gateway)
	if err != nil {
		return errors.New("--gateway must be a base URL using https (http only for localhost)")
	}
	kf, err := workloadclient.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := kf.Key()
	if err != nil {
		return err
	}
	run := *runFlag
	if run == "" {
		run = kf.RunID
	}
	if _, err := ids.ParseUUID(run); err != nil {
		return errors.New("--run must be a run id (pclaw run start)")
	}
	token, err := a.proxyTokens(ctx, kf, *tokenFile)
	if err != nil {
		return err
	}
	rt := a.http.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	p := &proxy{
		endpoint: base + "/mcp/" + url.PathEscape(*conn), run: run, out: a.stdout, log: a.stderr,
		client: &http.Client{
			Transport:     &workloadclient.Transport{Key: key, Base: rt, Token: token},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return p.serve(ctx, a.stdin)
}

// proxyTokens returns the workload token source: the token in tokenFile,
// or tokens issued by the key file's server and renewed halfway through
// each one's lifetime until ctx ends (workloadclient.Renewer).
func (a *app) proxyTokens(ctx context.Context, kf workloadclient.KeyFile, tokenFile string) (func() string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile) //nolint:gosec // G304: operator-chosen path
		if err != nil {
			return nil, err
		}
		tok := strings.TrimSpace(string(b))
		return func() string { return tok }, nil
	}
	if kf.Server == "" || kf.Identifier == "" {
		return nil, errors.New("the key file is not enrolled yet: run pclaw workload enroll")
	}
	wc, err := a.workloadClient(kf.Server, kf)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var cur string
	tr := &tokenRenewal{a: a, wc: wc, identifier: kf.Identifier, name: "pclaw mcp proxy"}
	r := tr.renewer(func(iss workloadclient.Issued) error {
		mu.Lock()
		cur = iss.Token
		mu.Unlock()
		return nil
	})
	if err := r.Renew(ctx); err != nil {
		return nil, fmt.Errorf("workload token: %w", err)
	}
	go func() {
		var refusal *workloadclient.RefusalError
		if err := r.Run(ctx); errors.As(err, &refusal) {
			inst, _ := pap.ParseInstance(kf.Identifier)
			tr.report(refusalHelp(refusal.Code, inst, "the key file", kf.Server) + " Requests fail from now on.")
		} else if err != nil {
			tr.report(err.Error())
		}
	}()
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}, nil
}

// proxy forwards one stdio client's messages to the gateway.
type proxy struct {
	endpoint, run string
	client        *http.Client
	out, log      io.Writer

	// A 2025-11-25 client's session: its initialize message (replayed when
	// the gateway ended the session), the version agreed and the id.
	initialize []byte
	version    string
	session    string
	// declared are the x-mcp-header parameters of each tool, from the last
	// 2026-07-28 tool list.
	declared map[string][]mcpheader.Param
	lists    int
}

// serve forwards messages until the client closes stdin or ctx ends.
func (p *proxy) serve(ctx context.Context, in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), proxyMaxMessage+1)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return nil // shutdown, not a failure
		default:
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		for _, answer := range p.forward(ctx, bytes.Clone(line)) {
			if _, err := fmt.Fprintf(p.out, "%s\n", answer); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the MCP client: %w", err)
	}
	return nil
}

// message is what the proxy reads of a client message.
type message struct {
	ID     jsontext.Value `json:"id,omitzero"`
	Method string         `json:"method"`
	Params struct {
		Meta      map[string]jsontext.Value `json:"_meta"`
		Name      string                    `json:"name"`
		URI       string                    `json:"uri"`
		TaskID    string                    `json:"taskId"`
		Arguments jsontext.Value            `json:"arguments"`
	} `json:"params"`
}

// forward sends one message and returns the lines to write back.
func (p *proxy) forward(ctx context.Context, line []byte) [][]byte {
	if line[0] == '[' {
		return [][]byte{rpcFailure(nil, -32600, "batches are not accepted: send one message per line")}
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		return [][]byte{rpcFailure(nil, -32700, "parse error: one JSON-RPC message per line")}
	}
	if m.Method == "" {
		return nil // an answer to a server request: the gateway sends none
	}
	modern := ""
	_ = json.Unmarshal(m.Params.Meta["io.modelcontextprotocol/protocolVersion"], &modern)
	if m.Method == "initialize" {
		p.initialize, p.session, p.version = line, "", ""
	}
	status, header, body, err := p.post(ctx, m, modern, line)
	if err == nil && modern == "" && m.Method != "initialize" && p.session != "" && status == http.StatusNotFound && p.initialize != nil {
		// The gateway ended the session (idle, expired or restarted): open
		// a new one with the client's own initialize, then send again.
		if p.reopen(ctx) {
			status, header, body, err = p.post(ctx, m, modern, line)
		}
	}
	if err == nil && modern != "" && m.Method == "tools/call" && status == http.StatusBadRequest && headerMismatch(body) {
		// The tool's declared parameter headers are unknown here or
		// changed: the gateway refused before deciding anything, so list
		// the tools and send once more.
		if p.relist(ctx, m, modern) {
			status, header, body, err = p.post(ctx, m, modern, line)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(p.log, "pclaw mcp proxy: %s: %v\n", m.Method, err)
		if len(m.ID) == 0 {
			return nil
		}
		return [][]byte{rpcFailure(m.ID, -32603, "the PantherClaw gateway is unreachable")}
	}
	if m.Method == "initialize" && status == http.StatusOK {
		p.adopt(header, body)
	}
	answers := answersOf(header, body)
	if modern != "" && m.Method == "tools/list" && status == http.StatusOK {
		p.learn(answers)
	}
	if len(answers) == 0 && len(m.ID) > 0 {
		return [][]byte{rpcFailure(m.ID, -32603, fmt.Sprintf("the gateway answered HTTP %d", status))}
	}
	return answers
}

// post sends one message with the request headers it implies.
func (p *proxy) post(ctx context.Context, m message, modern string, body []byte) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, proxyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("PAP-Run-Id", p.run)
	switch {
	case modern != "":
		// 2026-07-28: every request names its version, method and target.
		req.Header.Set("MCP-Protocol-Version", modern)
		req.Header.Set("Mcp-Method", m.Method)
		if name := target(m); name != "" {
			req.Header.Set("Mcp-Name", mcpheader.Encode(name))
		}
		if m.Method == "tools/call" {
			// Arguments that cannot be mirrored go without: the gateway
			// says what is wrong.
			mirrored, _ := mcpheader.Mirror(p.declared[m.Params.Name], m.Params.Arguments)
			for k, vs := range mirrored {
				req.Header[k] = vs
			}
		}
	case m.Method != "initialize":
		req.Header.Set("MCP-Protocol-Version", p.versionOrDefault())
		if p.session != "" {
			req.Header.Set("Mcp-Session-Id", p.session)
		}
	}
	res, err := p.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, proxyMaxAnswer+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(b) > proxyMaxAnswer {
		return 0, nil, nil, errors.New("the gateway's answer is too large")
	}
	return res.StatusCode, res.Header, b, nil
}

// reopen replays the client's initialize and announces it initialized.
func (p *proxy) reopen(ctx context.Context) bool {
	var m message
	if json.Unmarshal(p.initialize, &m) != nil {
		return false
	}
	p.session = ""
	status, header, body, err := p.post(ctx, m, "", p.initialize)
	if err != nil || status != http.StatusOK {
		return false
	}
	p.adopt(header, body)
	note := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	_, _, _, err = p.post(ctx, message{Method: "notifications/initialized"}, "", note)
	return err == nil
}

// adopt keeps the session and version an initialize answer agreed.
func (p *proxy) adopt(header http.Header, body []byte) {
	p.session = header.Get("Mcp-Session-Id")
	var r struct {
		Result struct {
			Version string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &r) == nil {
		p.version = r.Result.Version
	}
}

func (p *proxy) versionOrDefault() string {
	if p.version != "" {
		return p.version
	}
	return legacyVersion
}

// target is what Mcp-Name carries for a method: the tool or prompt name,
// the resource URI or the task id.
func target(m message) string {
	switch {
	case m.Method == "tools/call" || m.Method == "prompts/get":
		return m.Params.Name
	case m.Method == "resources/read":
		return m.Params.URI
	case strings.HasPrefix(m.Method, "tasks/"):
		return m.Params.TaskID
	}
	return ""
}

// answersOf returns the JSON-RPC messages of a gateway answer, one per
// line: one JSON object, or the events of a stream.
func answersOf(header http.Header, body []byte) [][]byte {
	ct, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	var raw [][]byte
	switch ct {
	case "application/json":
		raw = [][]byte{body}
	case "text/event-stream":
		var data bytes.Buffer
		for line := range strings.Lines(string(body) + "\n") {
			line = strings.TrimRight(line, "\r\n")
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				data.WriteString(strings.TrimPrefix(v, " "))
				data.WriteByte('\n')
				continue
			}
			if line == "" && data.Len() > 0 {
				raw = append(raw, bytes.Clone(bytes.TrimSuffix(data.Bytes(), []byte("\n"))))
				data.Reset()
			}
		}
	}
	var out [][]byte
	for _, r := range raw {
		v := jsontext.Value(r)
		if v.Compact() == nil && v.Kind() == '{' {
			out = append(out, v)
		}
	}
	return out
}

func rpcFailure(id jsontext.Value, code int, msg string) []byte {
	if len(id) == 0 {
		id = jsontext.Value("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	return b
}

// learn keeps the x-mcp-header parameters of each tool in a 2026-07-28
// tool list. A tool whose declarations break the specification is
// reported and gets none (the gateway serves only reviewed schemas, which
// never do).
func (p *proxy) learn(answers [][]byte) {
	for _, a := range answers {
		var r struct {
			Result *struct {
				Tools []struct {
					Name        string         `json:"name"`
					InputSchema jsontext.Value `json:"inputSchema"`
				} `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(a, &r) != nil || r.Result == nil {
			continue
		}
		p.declared = map[string][]mcpheader.Param{}
		for _, t := range r.Result.Tools {
			params, err := mcpheader.Parse(t.InputSchema)
			if err != nil {
				_, _ = fmt.Fprintf(p.log, "pclaw mcp proxy: tool %q: %v\n", t.Name, err)
				continue
			}
			p.declared[t.Name] = params
		}
	}
}

// relist asks the gateway for its tools, with a call's version and
// client metadata, and learns their declared parameter headers.
func (p *proxy) relist(ctx context.Context, call message, modern string) bool {
	meta := map[string]jsontext.Value{}
	for _, k := range []string{"io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientInfo", "io.modelcontextprotocol/clientCapabilities"} {
		if v, ok := call.Params.Meta[k]; ok {
			meta[k] = v
		}
	}
	p.lists++
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "pclaw-proxy-" + strconv.Itoa(p.lists), "method": "tools/list", "params": map[string]any{"_meta": meta},
	}, json.Deterministic(true))
	if err != nil {
		return false
	}
	status, header, answer, err := p.post(ctx, message{Method: "tools/list"}, modern, body)
	if err != nil || status != http.StatusOK {
		return false
	}
	p.learn(answersOf(header, answer))
	return true
}

// headerMismatch reports whether an answer is the gateway's HeaderMismatch
// error (-32020).
func headerMismatch(body []byte) bool {
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	return json.Unmarshal(body, &r) == nil && r.Error != nil && r.Error.Code == -32020
}
