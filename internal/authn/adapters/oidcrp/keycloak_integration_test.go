// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package oidcrp_test

import (
	"context"
	"crypto/rand"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// TestIntKeycloakDevRealm signs alice in to the development realm
// (deploy/keycloak) through the relying party: discovery, PKCE, nonce, the
// RFC 9207 iss parameter and ID-token verification against a real Keycloak.
// Opt-in: `task up PROFILE=identity`, then PC_TEST_KEYCLOAK_URL=http://127.0.0.1:8180.
func TestIntKeycloakDevRealm(t *testing.T) {
	base := os.Getenv("PC_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("PC_TEST_KEYCLOAK_URL not set")
	}
	ctx := context.Background()
	p, err := oidcrp.New(oidcrp.Config{
		Name: "keycloak", Issuer: base + "/realms/pantherclaw", ClientID: "pantherclaw",
		ClientSecret: pclog.NewSecret([]byte("pantherclaw-dev-only-client-secret")), AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if need, err := p.RequireIssParam(ctx); err != nil || !need {
		t.Fatalf("Keycloak should advertise RFC 9207: %v %v", need, err)
	}
	const redirect = "http://127.0.0.1:8080/oauth2/callback/keycloak" // registered in the realm
	nonce, verifier, state := rand.Text(), rand.Text()+rand.Text(), rand.Text()
	authURL, err := p.AuthCodeURL(ctx, state, nonce, verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// do returns the redirect target and the page; the body is always closed.
	do := func(method, u string, form url.Values) (string, string) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequestWithContext(ctx, method, u, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		page, _ := io.ReadAll(res.Body)
		return res.Header.Get("Location"), string(page)
	}
	_, page := do(http.MethodGet, authURL, nil)
	m := formAction.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no Keycloak login form")
	}
	location, _ := do(http.MethodPost, html.UnescapeString(m[1]), url.Values{"username": {"alice"}, "password": {"alice-dev-only"}})
	back, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(back.String(), redirect) {
		t.Fatalf("Keycloak redirected to %q", location)
	}
	q := back.Query()
	if q.Get("state") != state || q.Get("iss") != p.Issuer() {
		t.Fatalf("authorization response state/iss = %q/%q", q.Get("state"), q.Get("iss"))
	}
	claims, err := p.Exchange(ctx, q.Get("code"), verifier, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Nonce != nonce || claims.Email != "alice@example.test" || !claims.EmailVerified || claims.Issuer != p.Issuer() {
		t.Fatalf("claims = %+v", claims)
	}
	// A code can be exchanged only once, and only with its PKCE verifier.
	if _, err := p.Exchange(ctx, q.Get("code"), verifier, redirect); err == nil {
		t.Fatal("authorization code accepted twice")
	}
}
