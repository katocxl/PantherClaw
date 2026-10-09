// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const audience = "https://pantherclaw.example.test"

func subjects(t *testing.T, idp *oidctest.Provider, aud string) oidcrp.Subjects {
	t.Helper()
	p, err := oidcrp.New(oidcrp.Config{
		Name: "corp", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(), SubjectTokenAudience: aud,
	})
	if err != nil {
		t.Fatal(err)
	}
	return oidcrp.Subjects{p}
}

func claims(idp *oidctest.Provider, now time.Time) map[string]any {
	return map[string]any{
		"iss": idp.Issuer(), "sub": "alice", "aud": []string{audience}, "jti": "t-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

// TestHR145_SubjectTokensAreFreshSignedJWTsForPantherClaw.
func TestHR145_SubjectTokensAreFreshSignedJWTsForPantherClaw(t *testing.T) {
	idp := oidctest.New(t)
	s := subjects(t, idp, audience)
	ctx, now := context.Background(), time.Now()
	got, err := s.VerifySubject(ctx, idp.Token(claims(idp, now), ""), false, now)
	if err != nil || got.Subject != "alice" || got.Issuer != idp.Issuer() || got.JTI != "t-1" {
		t.Fatalf("ID token: %+v, %v", got, err)
	}
	if _, err := s.VerifySubject(ctx, idp.Token(claims(idp, now), "at+jwt"), true, now); err != nil {
		t.Fatalf("access token: %v", err)
	}
	with := func(k string, v any) map[string]any {
		c := claims(idp, now)
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	enc := base64.RawURLEncoding.EncodeToString
	for name, tc := range map[string]struct {
		token  string
		access bool
	}{
		"access token without at+jwt": {idp.Token(claims(idp, now), ""), true},
		"ID token typed at+jwt":       {idp.Token(claims(idp, now), "at+jwt"), false},
		"another audience":            {idp.Token(with("aud", []string{"https://other.test"}), ""), false},
		"issued 7 minutes ago":        {idp.Token(with("iat", now.Add(-7*time.Minute).Unix()), ""), false},
		"issued in the future":        {idp.Token(with("iat", now.Add(3*time.Minute).Unix()), ""), false},
		"no iat":                      {idp.Token(with("iat", nil), ""), false},
		"expired":                     {idp.Token(with("exp", now.Add(-time.Second).Unix()), ""), false},
		"no subject":                  {idp.Token(with("sub", nil), ""), false},
		"another issuer":              {idp.Token(with("iss", "https://evil.test"), ""), false},
		"opaque":                      {"2YotnFZFEjr1zCsicMWpAA", false},
		"unsigned":                    {enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"iss":"`+idp.Issuer()+`","sub":"alice"}`)) + ".", false},
		"tampered":                    {idp.Token(claims(idp, now), "")[:40] + "x" + idp.Token(claims(idp, now), "")[41:], false},
	} {
		if _, err := s.VerifySubject(ctx, tc.token, tc.access, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A provider without subject_token_audience accepts none.
	if _, err := subjects(t, idp, "").VerifySubject(ctx, idp.Token(claims(idp, now), ""), false, now); err == nil {
		t.Error("a provider not configured for subject tokens accepted one")
	}
}
