// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhttp_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
)

// follow walks redirects and the continue page until the account page.
func (s *site) follow(t *testing.T, u string) {
	t.Helper()
	for range 6 {
		resp := s.get(t, u)
		switch {
		case resp.StatusCode == http.StatusOK && strings.Contains(resp.Body, "Your account"):
			return
		case resp.StatusCode == http.StatusOK && strings.Contains(resp.Body, "Signed in"):
			u = s.url + authnapp.AccountPath
		case resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound:
			base, _ := url.Parse(u)
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			u = base.ResolveReference(loc).String()
		default:
			t.Fatalf("GET %s: %d %s", u, resp.StatusCode, resp.Body)
		}
	}
	t.Fatal("did not reach the account page")
}

// postJSONBody posts body from the page's origin with the CSRF proof.
func (s *site) postJSONBody(t *testing.T, path string, body any) (int, map[string]jsontext.Value) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url+path, strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", s.url)
	req.Header.Set(webhttp.CSRFHeader, "1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]jsontext.Value{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestHR155_AKeyLifecycleThroughTheAccountPage(t *testing.T) {
	s := newSite(t)
	a, err := webauthntest.New(s.url, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	// Without a recent sign-in the page is told where to sign in again.
	s.signIn(t)
	status, body := s.postJSONBody(t, authnapp.AccountPath+"/keys/registration-options", map[string]any{})
	if status != http.StatusForbidden || string(body["error"]) != `"recent_auth_required"` {
		t.Fatalf("registration options without a recent sign-in: %d %v", status, body)
	}
	var signIn string
	if err := json.Unmarshal(body["sign_in"], &signIn); err != nil {
		t.Fatal(err)
	}
	s.follow(t, s.url+signIn)

	// Add a key, as the page script does.
	status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys/registration-options", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("registration options: %d %v", status, body)
	}
	resp, err := a.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys", map[string]any{
		"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp),
	})
	if status != http.StatusOK {
		t.Fatalf("add key: %d %v", status, body)
	}
	var keyID string
	_ = json.Unmarshal(body["id"], &keyID)
	page := s.get(t, s.url+authnapp.AccountPath)
	if !strings.Contains(page.Body, "Desk key") || strings.Contains(page.Body, "Verified with a security key") {
		t.Fatalf("account page after adding: %s", page.Body)
	}

	// Step up: the session cookie changes and the page says so.
	before := s.cookie(t)
	status, body = s.postJSONBody(t, authnapp.AccountPath+"/step-up-options", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("step-up options: %d %v", status, body)
	}
	resp, err = a.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if status, body = s.postJSONBody(t, authnapp.AccountPath+"/step-up", map[string]any{
		"ceremony": body["ceremony"], "response": jsontext.Value(resp),
	}); status != http.StatusOK {
		t.Fatalf("step-up: %d %v", status, body)
	}
	if after := s.cookie(t); after == "" || after == before {
		t.Fatal("step-up did not replace the session cookie")
	}
	if page := s.get(t, s.url+authnapp.AccountPath); !strings.Contains(page.Body, "Verified with a security key") {
		t.Fatal("account page does not show the step-up")
	}

	// Rename and remove.
	if status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys/"+keyID+"/rename", map[string]any{"name": "Travel key"}); status != http.StatusOK {
		t.Fatalf("rename: %d %v", status, body)
	}
	if status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys/"+keyID+"/remove", map[string]any{}); status != http.StatusOK {
		t.Fatalf("remove: %d %v", status, body)
	}
	if page := s.get(t, s.url+authnapp.AccountPath); strings.Contains(page.Body, "Travel key") || !strings.Contains(page.Body, "No security keys yet") {
		t.Fatalf("account page after removal: %s", page.Body)
	}
}

// cookie returns the current session cookie value in the jar.
func (s *site) cookie(t *testing.T) string {
	t.Helper()
	u, _ := url.Parse(s.url)
	for _, c := range s.client.Jar.Cookies(u) {
		if c.Name == "pc_session" {
			return c.Value
		}
	}
	return ""
}
