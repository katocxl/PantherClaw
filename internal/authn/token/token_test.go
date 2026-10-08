// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package token_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	issuer   = "https://pc.example.test"
	audience = "pantherclaw-api"
)

func registry(t *testing.T) *keys.Registry {
	t.Helper()
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func grant() token.Grant {
	return token.Grant{
		Org:       ids.New[ids.Org](),
		Principal: domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()},
		Session:   ids.NewV7(), ClientID: "pclaw",
	}
}

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func TestIssueAndVerify(t *testing.T) {
	svc, err := token.New(registry(t), issuer, audience)
	if err != nil {
		t.Fatal(err)
	}
	g := grant()
	tok, exp, err := svc.Issue(g, t0)
	if err != nil {
		t.Fatal(err)
	}
	if exp != t0.Add(token.TTL) {
		t.Fatalf("expiry %v", exp)
	}
	v, err := svc.Verify(tok, t0.Add(token.TTL-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if v.Grant != g || v.ID == "" || !v.ExpiresAt.Equal(exp) {
		t.Fatalf("verified %+v, want grant %+v", v, g)
	}
}

// payload re-signs arbitrary claims with the real access-token key, to test
// claim checks independently of the signature.
func signWith(t *testing.T, reg *keys.Registry, purpose keys.Purpose, typ string, claims map[string]any) string {
	t.Helper()
	s, err := reg.Signer(purpose)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Sign(typ, b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func goodClaims(g token.Grant) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": audience, "sub": g.Principal.ID.String(), "pc_org": g.Org.String(),
		"pc_ptyp": "user", "sid": g.Session.String(), "client_id": "pclaw", "jti": ids.NewV7().String(),
		"iat": t0.Unix(), "nbf": t0.Unix(), "exp": t0.Add(token.TTL).Unix(),
	}
}

// TestT032_AccessTokenClaimsAreChecked: wrong issuer or audience, expired,
// not-yet-valid, overlong, malformed or extended tokens are rejected even
// with a valid signature.
func TestT032_AccessTokenClaimsAreChecked(t *testing.T) {
	reg := registry(t)
	svc, _ := token.New(reg, issuer, audience)
	g := grant()
	cases := map[string]func(map[string]any){
		"ok":                func(map[string]any) {},
		"wrong issuer":      func(c map[string]any) { c["iss"] = "https://evil.test" },
		"wrong audience":    func(c map[string]any) { c["aud"] = "other-api" },
		"audience array":    func(c map[string]any) { c["aud"] = []string{audience} },
		"expired":           func(c map[string]any) { c["exp"] = t0.Unix(); c["iat"] = t0.Add(-time.Minute).Unix() },
		"issued in future":  func(c map[string]any) { c["iat"] = t0.Add(time.Hour).Unix() },
		"not yet valid":     func(c map[string]any) { c["nbf"] = t0.Add(time.Hour).Unix() },
		"overlong lifetime": func(c map[string]any) { c["exp"] = t0.Add(24 * time.Hour).Unix() },
		"no jti":            func(c map[string]any) { delete(c, "jti") },
		"unknown claim":     func(c map[string]any) { c["scope"] = "admin" },
		"bad org":           func(c map[string]any) { c["pc_org"] = "00000000-0000-0000-0000-000000000000" },
		"bad subject":       func(c map[string]any) { c["sub"] = "admin" },
		"bad principal":     func(c map[string]any) { c["pc_ptyp"] = "gateway" },
		"bad session":       func(c map[string]any) { c["sid"] = "" },
	}
	for name, mutate := range cases {
		c := goodClaims(g)
		mutate(c)
		_, err := svc.Verify(signWith(t, reg, keys.PurposeAccessTokens, token.Type, c), t0.Add(time.Minute))
		if (err == nil) != (name == "ok") {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && !errors.Is(err, token.ErrInvalid) {
			t.Errorf("%s: error %v does not wrap ErrInvalid", name, err)
		}
	}
}

// TestT032_SubstitutedTokensAreRejected: a permit, receipt or workload token
// (other purposes' keys or types) is never accepted as an access token, nor
// is a token from another deployment.
func TestT032_SubstitutedTokensAreRejected(t *testing.T) {
	reg := registry(t)
	svc, _ := token.New(reg, issuer, audience)
	c := goodClaims(grant())
	for name, tok := range map[string]string{
		"permit key":          signWith(t, reg, keys.PurposePermits, token.Type, c),
		"receipt key":         signWith(t, reg, keys.PurposeReceipts, token.Type, c),
		"workload-token key":  signWith(t, reg, keys.PurposeWorkloadTokens, token.Type, c),
		"access key, jwt typ": signWith(t, reg, keys.PurposeAccessTokens, "JWT", c),
		"other deployment":    signWith(t, registry(t), keys.PurposeAccessTokens, token.Type, c),
	} {
		if _, err := svc.Verify(tok, t0.Add(time.Minute)); !errors.Is(err, token.ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// TestT032_AlgorithmConfusionIsRejected: alg none, HS256 keyed with the
// public key, and a tampered payload are rejected (HR-095).
func TestT032_AlgorithmConfusionIsRejected(t *testing.T) {
	reg := registry(t)
	svc, _ := token.New(reg, issuer, audience)
	good, _, err := svc.Issue(grant(), t0)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]any
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatal(err)
	}
	enc := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	h["alg"] = "none"
	none := enc(h) + "." + parts[1] + "."
	h["alg"] = "HS256"
	signer, _ := reg.Signer(keys.PurposeAccessTokens)
	mac := hmac.New(sha256.New, signer.Public())
	mac.Write([]byte(enc(h) + "." + parts[1]))
	hs := enc(h) + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), `"user"`, `"service_account"`, 1))) + "." + parts[2]
	for name, tok := range map[string]string{"none": none, "HS256": hs, "tampered": tampered, "empty": "", "garbage": "a.b.c"} {
		if _, err := svc.Verify(tok, t0.Add(time.Minute)); !errors.Is(err, token.ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestIssueRejectsIncompleteGrant(t *testing.T) {
	svc, _ := token.New(registry(t), issuer, audience)
	for name, mutate := range map[string]func(*token.Grant){
		"no org":     func(g *token.Grant) { g.Org = ids.OrgID{} },
		"no session": func(g *token.Grant) { g.Session = ids.UUID{} },
		"no client":  func(g *token.Grant) { g.ClientID = "" },
		"bad kind":   func(g *token.Grant) { g.Principal.Kind = "gateway" },
	} {
		g := grant()
		mutate(&g)
		if _, _, err := svc.Issue(g, t0); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
	if _, err := token.New(nil, issuer, audience); err == nil {
		t.Error("New without keys accepted")
	}
}
