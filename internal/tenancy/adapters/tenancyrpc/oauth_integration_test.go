// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package tenancyrpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// bot is a service account with a registered Ed25519 key.
type bot struct {
	clientID string
	kid      string
	priv     ed25519.PrivateKey
	keyID    string
	saID     string
}

func (s *stack) bot(t *testing.T, adminTok, role string) bot {
	t.Helper()
	ctx := context.Background()
	_, acc := s.clients(adminTok)
	sac := s.saClient(adminTok)
	sa, err := sac.CreateServiceAccount(ctx, &pantherclawv1.CreateServiceAccountRequest{Name: "bot-" + strings.ReplaceAll(role, "_", "-")})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwk, _ := jose.JSONWebKey{Key: pub}.MarshalJSON()
	k, err := sac.AddServiceAccountKey(ctx, &pantherclawv1.AddServiceAccountKeyRequest{
		ServiceAccountId: sa.GetServiceAccount().GetId(), Algorithm: pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_EDDSA, PublicJwk: string(jwk),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acc.CreateRoleBinding(ctx, &pantherclawv1.CreateRoleBindingRequest{
		Role: role, PrincipalType: pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT, PrincipalId: sa.GetServiceAccount().GetId(),
		Scope: &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_ORG},
	}); err != nil {
		t.Fatal(err)
	}
	return bot{
		clientID: sa.GetServiceAccount().GetClientId(), kid: k.GetKey().GetKid(), priv: priv,
		keyID: k.GetKey().GetId(), saID: sa.GetServiceAccount().GetId(),
	}
}

func (b bot) assertion(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": b.clientID, "sub": b.clientID, "aud": issuer + authnapp.TokenPath, "jti": ids.NewV7().String(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	opts := (&jose.SignerOptions{}).WithHeader("kid", b.kid).WithType("JWT")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: b.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sig.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

type tokenReply struct {
	status int
	body   map[string]any
}

func (s *stack) postToken(t *testing.T, form url.Values, hdr http.Header) tokenReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url+authnapp.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header[k] = v
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("token response without Cache-Control: no-store")
	}
	return tokenReply{status: res.StatusCode, body: body}
}

func clientCredentials(clientID, assertion string) url.Values {
	return url.Values{
		"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {assertion},
	}
}

func TestIntPrivateKeyJWTClientCredentials(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := s.org(t, "acme")
	_, adminTok := s.login(t, org, "admin@acme.test", td.RoleOrgAdmin)
	b := s.bot(t, adminTok, "viewer")

	asrt := b.assertion(t, nil)
	r := s.postToken(t, clientCredentials(b.clientID, asrt), nil)
	if r.status != http.StatusOK || r.body["token_type"] != "Bearer" || r.body["expires_in"] != float64(900) {
		t.Fatalf("token response %d %v", r.status, r.body)
	}
	at, _ := r.body["access_token"].(string)
	_, acc := s.clients(at)
	me, err := acc.WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{})
	if err != nil || me.GetPrincipal().GetType() != pantherclawv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT || me.GetPrincipal().GetId() != b.saID {
		t.Fatalf("WhoAmI as the service account = %v, %v", me, err)
	}
	// The same assertion again is a replay.
	if r := s.postToken(t, clientCredentials(b.clientID, asrt), nil); r.status != http.StatusUnauthorized || r.body["error"] != "invalid_client" {
		t.Errorf("replayed assertion: %d %v", r.status, r.body)
	}
	// Revoking the key the token was obtained with stops the token.
	if _, err := s.saClient(adminTok).RevokeServiceAccountKey(ctx, &pantherclawv1.RevokeServiceAccountKeyRequest{
		ServiceAccountId: b.saID, KeyId: b.keyID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := acc.WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("token after key revocation: %v", err)
	}
	if r := s.postToken(t, clientCredentials(b.clientID, b.assertion(t, nil)), nil); r.status != http.StatusUnauthorized {
		t.Errorf("assertion with a revoked key: %d %v", r.status, r.body)
	}
}

// TestHR095_TokenEndpointRejectsUnpinnedAlgorithms: none and HS256 keyed
// with the registered public key never authenticate a service account.
func TestHR095_TokenEndpointRejectsUnpinnedAlgorithms(t *testing.T) {
	s := newStack(t)
	org := s.org(t, "acme")
	_, adminTok := s.login(t, org, "admin@acme.test", td.RoleOrgAdmin)
	b := s.bot(t, adminTok, "viewer")
	good := strings.Split(b.assertion(t, nil), ".")
	enc := func(m map[string]any) string {
		x, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(x)
	}
	none := enc(map[string]any{"alg": "none", "kid": b.kid}) + "." + good[1] + "."
	hsHdr := enc(map[string]any{"alg": "HS256", "kid": b.kid})
	mac := hmac.New(sha256.New, b.priv.Public().(ed25519.PublicKey))
	mac.Write([]byte(hsHdr + "." + good[1]))
	hs := hsHdr + "." + good[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	for name, a := range map[string]string{"none": none, "HS256": hs} {
		if r := s.postToken(t, clientCredentials(b.clientID, a), nil); r.status != http.StatusUnauthorized || r.body["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, r.status, r.body)
		}
	}
}

// TestT032_TokenEndpointRejectsBadRequests: wrong audience, a client id of
// another account, Basic authentication, repeated or query parameters and
// unknown grants are refused with the right OAuth error.
func TestT032_TokenEndpointRejectsBadRequests(t *testing.T) {
	s := newStack(t)
	org := s.org(t, "acme")
	_, adminTok := s.login(t, org, "admin@acme.test", td.RoleOrgAdmin)
	b := s.bot(t, adminTok, "viewer")
	other := s.bot(t, adminTok, "developer")

	cases := map[string]struct {
		form   url.Values
		hdr    http.Header
		status int
		code   string
	}{
		"audience of another server": {clientCredentials(b.clientID, b.assertion(t, func(c map[string]any) { c["aud"] = "https://evil.test/oauth2/token" })), nil, 401, "invalid_client"},
		"assertion for another client": {clientCredentials(other.clientID, b.assertion(t, func(c map[string]any) {
			c["iss"], c["sub"] = other.clientID, other.clientID
		})), nil, 401, "invalid_client"},
		"basic auth":      {clientCredentials(b.clientID, b.assertion(t, nil)), http.Header{"Authorization": {"Basic eDp5"}}, 401, "invalid_client"},
		"unknown grant":   {url.Values{"grant_type": {"password"}}, nil, 400, "unsupported_grant_type"},
		"no grant":        {url.Values{}, nil, 400, "unsupported_grant_type"},
		"bad assert type": {url.Values{"grant_type": {"client_credentials"}, "client_id": {b.clientID}, "client_assertion_type": {"x"}, "client_assertion": {b.assertion(t, nil)}}, nil, 401, "invalid_client"},
	}
	for name, tc := range cases {
		if r := s.postToken(t, tc.form, tc.hdr); r.status != tc.status || r.body["error"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", name, r.status, r.body, tc.status, tc.code)
		}
	}
	// Repeated parameters are ambiguous (RFC 6749 §3.2).
	dup := clientCredentials(b.clientID, b.assertion(t, nil))
	dup.Add("client_id", other.clientID)
	if r := s.postToken(t, dup, nil); r.status != 400 || r.body["error"] != "invalid_request" {
		t.Errorf("duplicate parameter: %d %v", r.status, r.body)
	}
	mdReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, s.url+"/.well-known/oauth-authorization-server", nil)
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(mdReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var md map[string]any
	_ = json.UnmarshalRead(res.Body, &md)
	if md["token_endpoint"] != issuer+authnapp.TokenPath || md["issuer"] != issuer {
		t.Errorf("metadata = %v", md)
	}
}
