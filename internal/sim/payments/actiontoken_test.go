// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package payments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const testConnection = "01920000-0000-7000-8000-00000000c001"

// tokenWorld is a JWKS with an action-token key and a permits key, and a
// simulator requiring action tokens addressed to testConnection.
type tokenWorld struct {
	reg  *keys.Registry
	sim  *Server
	srv  *httptest.Server
	now  time.Time
	jwks *httptest.Server
}

func newTokenWorld(t *testing.T) *tokenWorld {
	t.Helper()
	w := &tokenWorld{reg: keys.NewRegistry(), now: time.Now()}
	for _, p := range []keys.Purpose{keys.PurposeActionTokens, keys.PurposePermits} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	w.jwks = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		b, _ := w.reg.JWKS()
		_, _ = rw.Write(b)
	}))
	t.Cleanup(w.jwks.Close)
	w.sim = New(Faults{}, pclog.Discard()).WithRequire(Require{ActionTokens: &ActionVerifier{
		JWKSURL: w.jwks.URL, Audience: testConnection, Now: func() time.Time { return w.now },
	}})
	w.srv = httptest.NewServer(w.sim.Handler())
	t.Cleanup(w.srv.Close)
	return w
}

// token signs action-token claims for body with the purpose's key, edited
// by edit.
func (w *tokenWorld) token(t *testing.T, purpose keys.Purpose, body string, edit func(map[string]any)) string {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	var b struct {
		Charge string `json:"charge"`
	}
	_ = json.Unmarshal([]byte(body), &b)
	c := map[string]any{
		"iss": "https://pc.example.test", "aud": testConnection, "jti": ids.NewV7().String(),
		"iat": w.now.Unix(), "exp": w.now.Add(time.Minute).Unix(),
		"pap": map[string]any{
			"v": 1, "txn": ids.NewV7().String(), "act": strings.Repeat("ab", 32), "bh": hex.EncodeToString(sum[:]),
			"op": "payments.refund.create", "target": map[string]string{"type": "payments.charge", "id": b.Charge},
		},
	}
	if edit != nil {
		edit(c)
	}
	payload, _ := json.Marshal(c)
	s, err := w.reg.Signer(purpose)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign(actionTokenType, payload)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (w *tokenWorld) refund(t *testing.T, body, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, w.srv.URL+"/v1/refunds", strings.NewReader(body))
	req.Header.Set("Idempotency-Key", "pc-"+ids.NewV7().String())
	if token != "" {
		req.Header.Set(HeaderAction, token)
	}
	res, err := w.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

const refundBody = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`

// TestHR188_TheTargetVerifiesActionTokens: a refund carrying a valid
// action token for its exact body, operation, target and connection is
// accepted once; the same token again, an expired one, one for another
// connection, body, operation or target, one signed by another PantherClaw
// key, and none at all are refused, and nothing is refunded.
func TestHR188_TheTargetVerifiesActionTokens(t *testing.T) {
	w := newTokenWorld(t)
	tok := w.token(t, keys.PurposeActionTokens, refundBody, nil)
	if code, body := w.refund(t, refundBody, tok); code != http.StatusOK {
		t.Fatalf("a valid token = %d %s", code, body)
	}
	for name, tc := range map[string]struct {
		token string
		body  string
		want  string
	}{
		"replayed": {tok, refundBody, "action_token_replayed"},
		"expired": {w.token(t, keys.PurposeActionTokens, refundBody, func(c map[string]any) {
			c["iat"], c["exp"] = w.now.Add(-2*time.Minute).Unix(), w.now.Add(-time.Minute).Unix()
		}), refundBody, "action_token_invalid"},
		"too long-lived": {w.token(t, keys.PurposeActionTokens, refundBody, func(c map[string]any) {
			c["exp"] = w.now.Add(10 * time.Minute).Unix()
		}), refundBody, "action_token_invalid"},
		"another connection": {w.token(t, keys.PurposeActionTokens, refundBody, func(c map[string]any) {
			c["aud"] = ids.NewV7().String()
		}), refundBody, "action_token_invalid"},
		"another body": {
			w.token(t, keys.PurposeActionTokens, refundBody, nil), strings.Replace(refundBody, "30.00", "300.00", 1), "action_token_invalid",
		},
		"another operation": {w.token(t, keys.PurposeActionTokens, refundBody, func(c map[string]any) {
			c["pap"].(map[string]any)["op"] = "payments.refund.get"
		}), refundBody, "action_token_invalid"},
		"another target": {
			w.token(t, keys.PurposeActionTokens, strings.Replace(refundBody, "ch_1", "ch_2", 1), func(c map[string]any) {
				sum := sha256.Sum256([]byte(refundBody))
				c["pap"].(map[string]any)["bh"] = hex.EncodeToString(sum[:])
			}), refundBody, "action_token_invalid",
		},
		"a permits key":   {w.token(t, keys.PurposePermits, refundBody, nil), refundBody, "action_token_invalid"},
		"no token":        {"", refundBody, "action_token_required"},
		"not a jws token": {"not.a.token", refundBody, "action_token_invalid"},
	} {
		if code, body := w.refund(t, tc.body, tc.token); code != http.StatusForbidden || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if s := w.sim.Stats(); s.Refunds != 1 || s.Refused != 10 {
		t.Fatalf("stats %+v", s)
	}
}

// TestS11_TheTargetRefusesRequestsWithoutTheCustodyCredential: a target
// that requires the credential PantherClaw holds refuses a direct call
// without it and accepts one with it; reading a refund back needs it too.
func TestS11_TheTargetRefusesRequestsWithoutTheCustodyCredential(t *testing.T) {
	sim := New(Faults{}, pclog.Discard()).WithRequire(Require{Token: "custody-secret"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	post := func(auth string) (int, string) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/refunds", strings.NewReader(refundBody))
		req.Header.Set("Idempotency-Key", "pc-"+ids.NewV7().String())
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	for _, auth := range []string{"", "Bearer wrong", "custody-secret"} {
		if code, body := post(auth); code != http.StatusUnauthorized || !strings.Contains(body, "credential_required") {
			t.Errorf("%q: %d %s", auth, code, body)
		}
	}
	code, body := post("Bearer custody-secret")
	var r struct {
		ID string `json:"id"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &r) != nil {
		t.Fatalf("with the credential: %d %s", code, body)
	}
	get := func(auth string) int {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/v1/refunds/"+r.ID, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	if get("") != http.StatusUnauthorized || get("Bearer custody-secret") != http.StatusOK {
		t.Fatal("reading a refund back")
	}
	if s := sim.Stats(); s.Refunds != 1 || s.Refused != 4 {
		t.Fatalf("stats %+v", s)
	}
}

// TestS12_TheRedirectFaultAnswersWithARedirect: with the fault on, a
// refund is answered with a 307 to the configured place and nothing is
// refunded.
func TestS12_TheRedirectFaultAnswersWithARedirect(t *testing.T) {
	sim := New(Faults{RedirectTo: "http://169.254.169.254/latest/meta-data/"}, pclog.Discard())
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/refunds", strings.NewReader(refundBody))
	req.Header.Set("Idempotency-Key", "pc-"+ids.NewV7().String())
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTemporaryRedirect || res.Header.Get("Location") != "http://169.254.169.254/latest/meta-data/" {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	if s := sim.Stats(); s.Refunds != 0 || s.Redirects != 1 {
		t.Fatalf("stats %+v", s)
	}
}
