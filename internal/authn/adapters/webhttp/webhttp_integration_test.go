// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhttp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/devicehttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type site struct {
	url    string
	org    ids.OrgID
	client *http.Client
	pool   *db.Pool
}

// newSite serves the device-flow and browser routes on one mux, as the
// server does, with an in-process provider that signs in alice.
func newSite(t *testing.T) *site {
	t.Helper()
	pool := dbtest.New(t).AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, _ := keys.GenerateSigningKey(p)
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	idp := oidctest.New(t)
	mux := http.NewServeMux()
	ts := httptest.NewUnstartedServer(mux)
	issuer := "http://" + ts.Listener.Addr().String()
	tokens, err := token.New(reg, issuer, token.Audience)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := oidcrp.New(oidcrp.Config{
		Name: "test", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := httpx.NewLimiter(10000, time.Minute, nil)
	oauth := oauthhttp.New(authnapp.NewOAuth(pool, tokens, issuer, clock.System{}, nil), issuer, limiter)
	oauth.Mount(mux)
	web, err := webhttp.New(authnapp.NewBrowser(pool, issuer, []authnapp.IdP{prov}, clock.System{}, nil), issuer, limiter, nil)
	if err != nil {
		t.Fatal(err)
	}
	web.Mount(mux)
	dev, err := devicehttp.New(authnapp.NewDevice(pool, tokens, issuer, []authnapp.IdP{prov}, clock.System{}, nil), issuer, limiter, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev.WithBrowserCallback(web.Callback).Mount(mux, oauth)
	ts.Start()
	t.Cleanup(ts.Close)

	s := &site{url: issuer, org: ids.New[ids.Org](), pool: pool}
	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'web')", s.org)
	exec(`INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, $3, 'alice', 'alice@example.test')`,
		s.org, ids.NewV7(), idp.Issuer())
	idp.SignIn(oidctest.User{Subject: "alice", Email: "alice@example.test", EmailVerified: true, Name: "Alice"})
	return s
}

func (s *site) get(t *testing.T, u string) result {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b), cookies: resp.Cookies()}
}

func (s *site) post(t *testing.T, path string) result {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url+path, strings.NewReader("{}"))
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
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b), cookies: resp.Cookies()}
}

// signIn opens the account page without a session and follows the sign-in
// to the end, as a browser would.
func (s *site) signIn(t *testing.T) {
	t.Helper()
	u := s.url + authnapp.AccountPath + "?org=" + s.org.String()
	for range 6 {
		resp := s.get(t, u)
		body := resp.Body
		switch {
		case resp.StatusCode == http.StatusOK && strings.Contains(body, "Your account"):
			return
		case resp.StatusCode == http.StatusOK && strings.Contains(body, "Signed in"):
			u = s.url + authnapp.AccountPath // the continue page's same-origin step
		case resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound:
			base, err1 := url.Parse(u)
			loc, err2 := url.Parse(resp.Header.Get("Location"))
			if err1 != nil || err2 != nil {
				t.Fatal(err1, err2)
			}
			u = base.ResolveReference(loc).String() // Location may be relative
		default:
			t.Fatalf("GET %s: %d %s", u, resp.StatusCode, body)
		}
	}
	t.Fatal("sign-in did not reach the account page")
}

func TestT051_BrowserSignInThroughTheSharedCallback(t *testing.T) {
	s := newSite(t)
	s.signIn(t)
	resp := s.get(t, s.url+authnapp.AccountPath)
	body := resp.Body
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice@example.test") || !strings.Contains(body, "This browser") {
		t.Fatalf("account page: %d %s", resp.StatusCode, body)
	}
	// Signing out ends the session; the account page then asks for sign-in.
	if resp := s.post(t, authnapp.LogoutPath); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp = s.get(t, s.url+authnapp.AccountPath+"?org="+s.org.String())
	if loc, err := url.Parse(resp.Header.Get("Location")); resp.StatusCode != http.StatusSeeOther || err != nil || loc.Path != authnapp.LoginPath {
		t.Fatalf("after sign-out: %d", resp.StatusCode)
	}
	var ended int
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.sessions WHERE end_reason = 'LOGOUT'").Scan(&ended)
	}); err != nil || ended != 1 {
		t.Fatalf("ended sessions %d (%v), want 1", ended, err)
	}
}

func TestHR152_DeviceStatesStayOnTheDevicePath(t *testing.T) {
	s := newSite(t)
	// A device-flow state on the shared callback goes to the device flow,
	// which does not know it; no browser session appears.
	resp := s.get(t, s.url+authnapp.CallbackPath+"test?"+url.Values{"state": {"pcs_" + strings.Repeat("0", 32) + "_" + strings.Repeat("a", 43)}}.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("device state: %d, want 400", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "pc_session" && c.Value != "" {
			t.Fatal("a device-flow callback set a browser session")
		}
	}
}
