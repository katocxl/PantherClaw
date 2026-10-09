// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

const txn = "01920000-0000-7000-8000-0000000000ff"

func mock(t *testing.T) (*defs.Package, *mapping.Mapper) {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

func mapped(t *testing.T, m *mapping.Mapper, tool, input string) actionir.ActionIR {
	t.Helper()
	p, err := m.MCP(context.Background(), mapping.Context{
		Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
		RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
		AgentInstance: "01920000-0000-7000-8000-000000000005",
	}, tool, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return p.Action
}

// TestHR075_TheOutboundRequestComesOnlyFromTheBoundAction: the refund is
// built from the template and the canonical action: the method, the path
// under the connection's base, the exact body with money split, and the
// transaction's idempotency key.
func TestHR075_TheOutboundRequestComesOnlyFromTheBoundAction(t *testing.T) {
	p, m := mock(t)
	create, _ := p.Definition("payments.refund.create")
	a := mapped(t, m, "create_refund", `{"charge":"ch_1","amount":"30","currency":"USD","reason":"duplicate"}`)
	r, err := Build("https://payments.example.test/api/", create, a, txn)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
	sum := sha256.Sum256([]byte(want))
	if r.Method != http.MethodPost || r.URL.String() != "https://payments.example.test/api/v1/refunds" || string(r.Body) != want ||
		!bytes.Equal(r.BodySHA256, sum[:]) || r.IdempotencyHeader != "Idempotency-Key" || r.IdempotencyKey != "pc-"+txn {
		t.Fatalf("built %+v %s", r, r.Body)
	}
	get, _ := p.Definition("payments.refund.get")
	g := mapped(t, m, "get_refund", `{"refund":"re_0192-ab"}`)
	r, err = Build("http://127.0.0.1:9090", get, g, txn)
	if err != nil || r.URL.String() != "http://127.0.0.1:9090/v1/refunds/re_0192-ab" || r.Body != nil || r.IdempotencyHeader != "" {
		t.Fatalf("get: %+v %v", r, err)
	}
}

// TestHR073_SubstitutionsCannotChangeThePathOrTheHost: a target id with a
// separator, an escape, a query, a fragment, userinfo or a dot segment is
// refused, and so is a base URL with a query or a template-less definition.
func TestHR073_SubstitutionsCannotChangeThePathOrTheHost(t *testing.T) {
	p, m := mock(t)
	get, _ := p.Definition("payments.refund.get")
	g := mapped(t, m, "get_refund", `{"refund":"re_1"}`)
	for _, id := range []string{"re_a/../b", "re_a%2fb", "re_a?x=1", "re_a#x", "re_a@evil.example", "..", ".", `re_a\b`} {
		bad := g
		bad.Target.ID = id
		if r, err := Build("https://payments.example.test", get, bad, txn); !errors.Is(err, ErrBuild) {
			t.Errorf("target %q: %v %v", id, r.URL, err)
		}
	}
	for _, base := range []string{"https://payments.example.test/?x=1", "ftp://payments.example.test", "https://user@payments.example.test", "/relative"} {
		if _, err := Build(base, get, g, txn); !errors.Is(err, ErrBuild) {
			t.Errorf("base %q: %v", base, err)
		}
	}
	none := *get
	none.Dispatch = nil
	if _, err := Build("https://payments.example.test", &none, g, txn); !errors.Is(err, ErrBuild) {
		t.Errorf("no template: %v", err)
	}
}

func localClient(t *testing.T, srv *httptest.Server, maxBytes int32) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, 5*time.Second, maxBytes, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func send(t *testing.T, c *Client, rawURL string) (Response, error) {
	t.Helper()
	u, _ := url.Parse(rawURL)
	req, err := c.HTTPRequest(context.Background(), Request{Method: http.MethodGet, URL: u})
	if err != nil {
		return Response{}, err
	}
	return c.Do(req)
}

// TestHR076_ResponsesAreCappedAndCompressionIsBounded: a long body is cut
// at the cap and marked; gzip the gateway did not ask for is decompressed
// only within a ratio; only the content type and request id come back.
func TestHR076_ResponsesAreCappedAndCompressionIsBounded(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 5000)
	var bomb bytes.Buffer
	z := gzip.NewWriter(&bomb)
	_, _ = z.Write(make([]byte, 1<<20))
	_ = z.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("X-Request-Id", "req_1")
		w.Header().Set("Set-Cookie", "session=x")
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(big)
		case "/bomb":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(bomb.Bytes())
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := localClient(t, srv, 1024)
	res, err := send(t, c, srv.URL+"/big")
	if err != nil || !res.Truncated || len(res.Body) != 1024 || res.RequestID != "req_1" {
		t.Fatalf("big: %d bytes truncated %v %v", len(res.Body), res.Truncated, err)
	}
	wide := localClient(t, srv, MaxResponse)
	res, err = send(t, wide, srv.URL+"/bomb")
	if err != nil || len(res.Body) > maxRatio*bomb.Len() || !res.Truncated {
		t.Fatalf("bomb: %d bytes from %d compressed, truncated %v %v", len(res.Body), bomb.Len(), res.Truncated, err)
	}
	res, err = send(t, c, srv.URL+"/redirect")
	if err != nil || res.Status != http.StatusFound {
		t.Fatalf("a redirect was followed: %d %v", res.Status, err)
	}
	if _, err := send(t, c, "https://elsewhere.example/x"); !errors.Is(err, ErrHost) {
		t.Fatalf("another host: %v", err)
	}
	strict, _ := NewClient(srv.URL, time.Second, 0, nil)
	if _, err := send(t, strict, srv.URL+"/big"); !errors.Is(err, httpx.ErrDestinationDenied) {
		t.Fatalf("a private address without an allowed prefix: %v", err)
	}
}

// TestHR076_TheCredentialNeverComesBackToTheAgent: the credential in
// plain, base64 and percent-encoded form is replaced.
func TestHR076_TheCredentialNeverComesBackToTheAgent(t *testing.T) {
	secret := []byte("sk_test_a+b/c=d?")
	body := strings.Join([]string{
		"plain " + string(secret),
		"std " + base64.StdEncoding.EncodeToString(secret),
		"raw " + base64.RawURLEncoding.EncodeToString(secret),
		"query " + url.QueryEscape(string(secret)),
		"path " + url.PathEscape(string(secret)),
	}, "\n")
	out := string(Redacted([]byte(body), secret))
	if strings.Contains(out, "sk_test") || strings.Count(out, "[REDACTED]") != 5 {
		t.Fatalf("redacted:\n%s", out)
	}
	if got := string(Redacted([]byte("abc"), []byte("ab"))); got != "abc" {
		t.Fatalf("a short credential matched by chance: %q", got)
	}
}
