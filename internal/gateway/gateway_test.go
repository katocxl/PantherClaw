// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

const (
	testToken = "dev-gateway-token-for-unit-tests-only-0001"
)

// fakeAuthority signs real permits with a real key registry.
type fakeAuthority struct {
	pantherclawv1connect.UnimplementedAuthorityServiceHandler
	t        *testing.T
	reg      *keys.Registry
	decision pb.Decision
	noPermit bool
	beginErr error
	// tamper edits the permit claims before signing; signWith picks the key.
	tamper   func(*permitClaims)
	signWith keys.Purpose

	mu        sync.Mutex
	authorize int
	begins    int
	records   []*pb.RecordExecutionRequest
	txn       string
	auth      string
}

func newFakeAuthority(t *testing.T) *fakeAuthority {
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeAuthority{t: t, reg: reg, decision: pb.Decision_DECISION_ALLOW, signWith: keys.PurposePermits}
}

func (f *fakeAuthority) Authorize(ctx context.Context, req *pb.AuthorizeRequest) (*pb.AuthorizeResponse, error) {
	p, err := actionir.Parse(req.GetActionIr())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "bad action")
	}
	info, _ := connect.CallInfoForServerContext(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorize++
	f.auth = info.RequestHeader().Get("Authorization")
	f.txn = ids.NewV7().String()
	res := &pb.AuthorizeResponse{Decision: f.decision, TransactionId: f.txn, ActionHash: p.HashHex()}
	if f.decision != pb.Decision_DECISION_ALLOW {
		res.Reasons = []*pb.Reason{{Code: "GRANT_AMOUNT_EXCEEDED", Decisive: true}}
		return res, nil
	}
	if f.noPermit {
		return res, nil
	}
	res.PermitId, res.Epoch = ids.NewV7().String(), 1
	var c permitClaims
	now := time.Now().Unix()
	c.Iss, c.Aud, c.Jti, c.Iat, c.Exp = "pantherclaw", "gw:gw-test", res.PermitId, now, now+5
	c.Pap.V, c.Pap.Org, c.Pap.Txn, c.Pap.Act, c.Pap.Epoch = 1, testOrg, f.txn, p.HashHex(), 1
	if f.tamper != nil {
		f.tamper(&c)
	}
	b, _ := json.Marshal(c)
	s, err := f.reg.Signer(f.signWith)
	if err != nil {
		return nil, err
	}
	res.Permit, _ = s.Sign(permitType, b)
	return res, nil
}

func (f *fakeAuthority) BeginDispatch(context.Context, *pb.BeginDispatchRequest) (*pb.BeginDispatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begins++
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &pb.BeginDispatchResponse{}, nil
}

func (f *fakeAuthority) RecordExecution(_ context.Context, req *pb.RecordExecutionRequest) (*pb.RecordExecutionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, req)
	return &pb.RecordExecutionResponse{Receipt: "receipt-jws"}, nil
}

// fakeTarget records what reached it.
type fakeTarget struct {
	status int
	hang   bool

	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

func (ft *fakeTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	ft.mu.Lock()
	ft.bodies = append(ft.bodies, string(b))
	ft.headers = append(ft.headers, r.Header.Clone())
	ft.mu.Unlock()
	if ft.hang {
		<-r.Context().Done()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ft.status)
	_, _ = io.WriteString(w, `{"id":"re_1","status":"succeeded","simulated":true}`)
}

func (ft *fakeTarget) calls() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.bodies)
}

func (ft *fakeTarget) req(i int) (string, http.Header) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.bodies[i], ft.headers[i]
}

type authSnap struct {
	authorize, begins int
	records           []*pb.RecordExecutionRequest
	txn, auth         string
}

func (f *fakeAuthority) snap() authSnap {
	f.mu.Lock()
	defer f.mu.Unlock()
	return authSnap{authorize: f.authorize, begins: f.begins, records: append([]*pb.RecordExecutionRequest(nil), f.records...), txn: f.txn, auth: f.auth}
}

func (s authSnap) outcome() pb.Outcome {
	if len(s.records) != 1 {
		return pb.Outcome_OUTCOME_UNSPECIFIED
	}
	return s.records[0].GetOutcome()
}

type harness struct {
	auth   *fakeAuthority
	target *fakeTarget
	gw     *Gateway
	url    string
}

// setup starts the fakes and the gateway; opts configure the fakes before
// any server goroutine starts.
func setup(t *testing.T, targetURL string, opts ...func(*harness)) *harness {
	t.Helper()
	h := &harness{auth: newFakeAuthority(t), target: &fakeTarget{status: http.StatusOK}}
	for _, o := range opts {
		o(h)
	}
	s, err := rpc.NewServer(rpc.Options{Logger: pclog.Discard(), Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAuthorityServiceHandler(s, h.auth)
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	mux.HandleFunc("GET /.well-known/pantherclaw/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		h.auth.mu.Lock()
		b, _ := h.auth.reg.JWKS()
		h.auth.mu.Unlock()
		_, _ = w.Write(b)
	})
	as := httptest.NewServer(mux)
	t.Cleanup(as.Close)
	if targetURL == "" {
		ts := httptest.NewServer(h.target)
		t.Cleanup(ts.Close)
		targetURL = ts.URL
	}
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.GatewayID, cfg.Org, cfg.DevWorkloads = "gw-test", testOrg, []string{testAgent}
	cfg.Authority.URL, cfg.Authority.TokenFile = as.URL, tok
	cfg.Target.URL, cfg.Target.AllowedPrefixes = targetURL, []string{"127.0.0.1/32"}
	cfg.Target.Timeout = config.Duration(500 * time.Millisecond)
	h.gw, err = New(&cfg, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(h.gw.Handler())
	t.Cleanup(gs.Close)
	h.url = gs.URL
	return h
}

const inbound = `{ "reason":"duplicate",  "currency":"USD","amount":"30.00","charge":"ch_1" }`

func (h *harness) post(t *testing.T, body string, hdr map[string]string) (int, result, http.Header) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+"/v1/refunds", strings.NewReader(body))
	req.Header.Set(HeaderDevWorkload, testAgent)
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set(HeaderActionID, ids.NewV7().String())
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
	var r result
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("response %q: %v", b, err)
	}
	return resp.StatusCode, r, resp.Header
}

func TestHR075_OutboundIsReSerialized(t *testing.T) {
	h := setup(t, "")
	code, r, hdr := h.post(t, inbound, map[string]string{"X-Forward-Me": "1", "Authorization": "Bearer agent-secret"})
	if code != http.StatusOK || r.Outcome != "ACCEPTED" || r.Receipt != "receipt-jws" {
		t.Fatalf("refund = %d %+v", code, r)
	}
	body, sent := h.target.req(0)
	if body != `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}` {
		t.Fatalf("outbound body %q is not the re-serialized action", body)
	}
	for _, name := range []string{"X-Forward-Me", "Authorization", HeaderDevWorkload, HeaderRunID, HeaderActionID} {
		if v := sent.Get(name); v != "" {
			t.Errorf("inbound header %s forwarded: %q", name, v)
		}
	}
	if h.auth.snap().auth != "Bearer "+testToken {
		t.Error("dev gateway token not presented to the Authority")
	}
	if !strings.Contains(strings.Join(hdr.Values("Server-Timing"), ","), "authz;dur=") {
		t.Errorf("Server-Timing = %v", hdr.Values("Server-Timing"))
	}
	// Extra inbound fields are refused before anything is authorized.
	if code, _, _ := h.post(t, strings.Replace(inbound, "}", `,"to":"acct_x"}`, 1), nil); code != http.StatusBadRequest || h.auth.snap().authorize != 1 {
		t.Fatalf("unknown field = %d, authorize calls %d", code, h.auth.snap().authorize)
	}
}

func TestHR008_IdempotencyKeyFromTransaction(t *testing.T) {
	h := setup(t, "")
	run, act := ids.NewV7().String(), ids.NewV7().String()
	if code, _, _ := h.post(t, inbound, map[string]string{HeaderRunID: run, HeaderActionID: act}); code != http.StatusOK {
		t.Fatalf("refund = %d", code)
	}
	_, sent := h.target.req(0)
	if got, txn := sent.Get("Idempotency-Key"), h.auth.snap().txn; got != "pc-"+txn {
		t.Fatalf("Idempotency-Key = %q, want pc-%s (the server-minted transaction id)", got, txn)
	}
}

// The full claim table is TestHR009_PermitVerification; this checks that a
// rejected permit stops the request before the commit point.
func TestHR009_BadPermitStopsBeforeDispatch(t *testing.T) {
	for name, mod := range map[string]func(*fakeAuthority){
		"action":      func(f *fakeAuthority) { f.tamper = func(c *permitClaims) { c.Pap.Act = strings.Repeat("0", 64) } },
		"receipt key": func(f *fakeAuthority) { f.signWith = keys.PurposeReceipts },
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, "", func(h *harness) { mod(h.auth) })
			code, r, _ := h.post(t, inbound, nil)
			if code != http.StatusBadGateway || r.Error != "permit_invalid" {
				t.Fatalf("= %d %+v, want 502 permit_invalid", code, r)
			}
			if s := h.auth.snap(); s.begins != 0 || h.target.calls() != 0 {
				t.Fatalf("bad permit reached BeginDispatch (%d) or the target (%d)", s.begins, h.target.calls())
			}
		})
	}
}

func TestOutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		status  int
		hang    bool
		code    int
		outcome pb.Outcome
	}{
		{status: http.StatusOK, code: http.StatusOK, outcome: pb.Outcome_OUTCOME_ACCEPTED},
		{status: http.StatusPaymentRequired, code: http.StatusBadGateway, outcome: pb.Outcome_OUTCOME_FAILED},
		{status: http.StatusInternalServerError, code: http.StatusGatewayTimeout, outcome: pb.Outcome_OUTCOME_UNKNOWN},
		{hang: true, code: http.StatusGatewayTimeout, outcome: pb.Outcome_OUTCOME_UNKNOWN},
	} {
		h := setup(t, "", func(h *harness) { h.target.status, h.target.hang = tc.status, tc.hang })
		code, _, _ := h.post(t, inbound, nil)
		if s := h.auth.snap(); code != tc.code || s.outcome() != tc.outcome {
			t.Errorf("target %d hang=%v: gateway %d, records %v", tc.status, tc.hang, code, s.records)
		}
	}
	// Nothing listening: the dial fails, nothing was sent, so FAILED.
	h := setup(t, deadURL(t))
	if code, _, _ := h.post(t, inbound, nil); code != http.StatusBadGateway || h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("dial failure = %d %v", code, h.auth.snap().records)
	}
}

func deadURL(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := "http://" + ln.Addr().String()
	_ = ln.Close()
	return u
}

func TestNothingDispatchedWithoutACommit(t *testing.T) {
	cases := map[string]struct {
		mod  func(*fakeAuthority)
		code int
	}{
		"deny":      {func(f *fakeAuthority) { f.decision = pb.Decision_DECISION_DENY }, http.StatusForbidden},
		"cannot":    {func(f *fakeAuthority) { f.decision = pb.Decision_DECISION_CANNOT_AUTHORIZE }, http.StatusForbidden},
		"duplicate": {func(f *fakeAuthority) { f.noPermit = true }, http.StatusConflict},
		"begin refused": {func(f *fakeAuthority) {
			f.beginErr = connect.NewError(connect.CodeFailedPrecondition, "PERMIT_EXPIRED")
		}, http.StatusConflict},
	}
	for name, tc := range cases {
		h := setup(t, "", func(h *harness) { tc.mod(h.auth) })
		code, r, _ := h.post(t, inbound, nil)
		if code != tc.code || h.target.calls() != 0 || len(h.auth.snap().records) != 0 {
			t.Errorf("%s: %d %+v, target calls %d", name, code, r, h.target.calls())
		}
		if name == "deny" && (r.Decision != "DENY" || len(r.Reasons) != 1) {
			t.Errorf("deny body %+v", r)
		}
	}
}

func TestDevWorkloadHeadersRequired(t *testing.T) {
	h := setup(t, "")
	for hdr, want := range map[string]int{HeaderDevWorkload: http.StatusUnauthorized, HeaderRunID: http.StatusBadRequest, HeaderActionID: http.StatusBadRequest} {
		if code, _, _ := h.post(t, inbound, map[string]string{hdr: ""}); code != want {
			t.Errorf("without %s: %d, want %d", hdr, code, want)
		}
	}
	if code, _, _ := h.post(t, inbound, map[string]string{HeaderDevWorkload: ids.NewV7().String()}); code != http.StatusUnauthorized {
		t.Errorf("unlisted workload: %d", code)
	}
	if h.auth.snap().authorize != 0 {
		t.Fatal("unauthenticated request reached the Authority")
	}
}

func TestAuthorityDownFailsClosed(t *testing.T) {
	dead := deadURL(t)
	h := setup(t, "")
	h.gw.authority = pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: time.Second}, dead)))
	if code, _, _ := h.post(t, inbound, nil); code != http.StatusServiceUnavailable || h.target.calls() != 0 {
		t.Fatalf("authority down = %d, target calls %d", code, h.target.calls())
	}
}
