// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/server"
)

// startM5 runs the server on http://localhost:<port> (WebAuthn needs a
// name) with an OIDC provider and a loopback SMTP relay.
func startM5(t *testing.T, p idp, relay *smtptest.Server) *m2Stack {
	t.Helper()
	d := dbtest.New(t)
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	apiAddr := freeAddr(t)
	_, port, _ := net.SplitHostPort(apiAddr)
	public := "http://localhost:" + port
	notifications := map[string]any{"concurrency": 2}
	if relay != nil {
		host, rport, _ := net.SplitHostPort(relay.Addr)
		p, _ := strconv.Atoi(rport)
		notifications["smtp"] = map[string]any{"host": host, "port": p, "tls": "none", "from": "pantherclaw@example.test"}
	}
	b, err := json.Marshal(map[string]any{
		"role": "all", "log": map[string]any{"level": "warn"}, "http": map[string]any{"addr": apiAddr},
		"database": map[string]any{
			"host": d.App.Host, "port": d.App.Port, "name": d.Name, "sslmode": "disable",
			"app_password_file":      writeFile(t, dir, "app-pw", d.App.Password.Reveal()),
			"migrator_password_file": writeFile(t, dir, "mig-pw", d.Migrator.Password.Reveal()),
			"max_conns":              10,
		},
		"kek_files": []string{kek}, "worker_concurrency": 2,
		"auth": map[string]any{
			"public_url": public, "api_key_env": "test",
			"oidc_providers": []map[string]any{{
				"name": "test", "issuer": p.issuer, "client_id": p.clientID, "allow_insecure_loopback": true,
				"client_secret_file": writeFile(t, dir, "idp-secret", []byte(p.secret)),
			}},
		},
		"notifications": notifications,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := writeFile(t, dir, "server.json", b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var logs syncBuffer
	go func() {
		defer close(done)
		if err := runServer(ctx, cfg, &logs); err != nil {
			t.Errorf("%v\n%s", err, logs.String())
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	waitReady(t, public, &logs)
	return &m2Stack{url: public, cfg: cfg, idp: p}
}

// browser is one person's browser: a cookie jar that does not follow
// redirects, so each hop is visible.
type browser struct {
	s *m2Stack
	c *http.Client
}

func newBrowser(s *m2Stack) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{s: s, c: &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

// signIn opens the sign-in page and follows it through the provider back
// to the account page.
func (b *browser) signIn(t *testing.T, org, subject, email string, recent bool) {
	t.Helper()
	q := url.Values{"org": {org}, "next": {"/account"}}
	if recent {
		q.Set("recent", "1")
	}
	res := get(t, b.c, b.s.url+"/login?"+q.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", res.StatusCode)
	}
	callback := b.s.idp.signIn(t, b.c, res.Location, subject, email)
	if res := get(t, b.c, callback); res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	if code, body := b.page(t, "/account"); code != http.StatusOK || !strings.Contains(body, email) {
		t.Fatalf("account page: %d", code)
	}
}

func (b *browser) page(t *testing.T, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, b.s.url+path, nil)
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// post sends a JSON request the way the account page script does.
func (b *browser) post(t *testing.T, path string, body any) (int, map[string]jsontext.Value) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, b.s.url+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PC-CSRF", "1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", b.s.url)
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out := map[string]jsontext.Value{}
	data, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(data, &out)
	return res.StatusCode, out
}

// TestE2E_M5p1_BrowserKeysAndNotifications is the M5 part 1 exit scenario:
// a person signs in with a browser, registers a security key, steps up,
// and gets the security notice by email; an administrator manages
// channels and signs the person out everywhere with pclaw.
func TestE2E_M5p1_BrowserKeysAndNotifications(t *testing.T) {
	relay := smtptest.New(t)
	s := startM5(t, inProcessIdP(t), relay)
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "create", "--config", s.cfg, "--name", "Acme"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org create: %d %s", code, errb.String())
	}
	org := orgCreated.FindStringSubmatch(out.String())[1]
	invite := pciToken.FindStringSubmatch(out.String())[1]
	alice := s.user(t, "alice", "alice@example.test")
	alice.login(t, org, invite)

	// Channels: a log channel and an email channel to the org admins; the
	// Community edition stops at three.
	for _, args := range [][]string{
		{"channel", "create", "--name", "ops", "--kind", "log", "--event", "security.*"},
		{"channel", "create", "--name", "admins", "--kind", "email", "--role", "org_admin", "--event", "security.*"},
		{"channel", "create", "--name", "spare", "--kind", "log", "--event", "channel.test"},
	} {
		if code, _, errs := alice.pclaw(t, args...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, errs)
		}
	}
	if code, _, errs := alice.pclaw(t, "channel", "create", "--name", "fourth", "--kind", "log", "--event", "security.*"); code != 1 ||
		!strings.Contains(errs, "3 notification channels") {
		t.Fatalf("fourth channel: %d %s", code, errs)
	}

	// Browser: a recent sign-in, then a security key from the account page.
	b := newBrowser(s)
	b.signIn(t, org, "alice", "alice@example.test", true)
	key, err := webauthntest.New(s.url, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	code, body := b.post(t, "/account/keys/registration-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("registration options: %d %v", code, body)
	}
	resp, err := key.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, "/account/keys", map[string]any{"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("add key: %d %v", code, body)
	}
	code, body = b.post(t, "/account/step-up-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("step-up options: %d %v", code, body)
	}
	if resp, err = key.Assert(body["options"]); err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, "/account/step-up", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("step-up: %d %v", code, body)
	}
	if _, page := b.page(t, "/account"); !strings.Contains(page, "Desk key") || !strings.Contains(page, "Verified with a security key") {
		t.Fatal("the account page does not show the key and the step-up")
	}

	// The worker emails the notice to alice once (personal notice and the
	// admins channel together) and logs it on the ops channel.
	deadline := time.Now().Add(30 * time.Second)
	for len(relay.Messages()) < 1 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	msgs := relay.Messages()
	if len(msgs) != 1 || msgs[0].To != "alice@example.test" || !strings.Contains(msgs[0].Data, "A security key was added") ||
		!strings.Contains(msgs[0].Data, "/account?org=") {
		t.Fatalf("security notice mail: %+v", msgs)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		_, list, _ := alice.pclaw(t, "delivery", "list", "--state", "delivered")
		if strings.Count(list, `"DELIVERY_STATE_DELIVERED"`) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deliveries not delivered: %s", list)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// pclaw sees the key and both sessions; signing alice out everywhere
	// ends the browser session too.
	if _, keys, _ := alice.pclaw(t, "key", "list"); !strings.Contains(keys, "Desk key") {
		t.Fatalf("key list: %s", keys)
	}
	_, sessions, _ := alice.pclaw(t, "session", "list")
	if !strings.Contains(sessions, "SESSION_KIND_BROWSER") || !strings.Contains(sessions, "SESSION_KIND_CLI") {
		t.Fatalf("session list: %s", sessions)
	}
	_, users, _ := alice.pclaw(t, "user", "list")
	var listed struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(users), &listed, json.RejectUnknownMembers(false)); err != nil || len(listed.Users) != 1 {
		t.Fatalf("user list: %s %v", users, err)
	}
	userID := listed.Users[0].ID
	if code, out, errs := alice.pclaw(t, "user", "revoke-sessions", userID); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke-sessions: %d %s %s", code, out, errs)
	}
	if code, _ := b.page(t, "/account?org="+org); code != http.StatusSeeOther {
		t.Fatalf("the browser session survived revoke-sessions: %d", code)
	}
}

// TestE2E_M5p1_BrowserSignInWithMockOAuth2Server signs in with a browser
// through navikt/mock-oauth2-server (CI), after a device login created the
// user.
func TestE2E_M5p1_BrowserSignInWithMockOAuth2Server(t *testing.T) {
	base := os.Getenv("PC_TEST_MOCK_OIDC_URL")
	if base == "" {
		t.Skip("PC_TEST_MOCK_OIDC_URL not set (docker compose --profile test starts mock-oauth2-server)")
	}
	s := startM5(t, mockOAuth2IdP(base), nil)
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "create", "--config", s.cfg, "--name", "Interop"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org create: %d %s", code, errb.String())
	}
	org := orgCreated.FindStringSubmatch(out.String())[1]
	invite := pciToken.FindStringSubmatch(out.String())[1]
	s.user(t, "alice", "alice@example.test").login(t, org, invite)
	newBrowser(s).signIn(t, org, "alice", "alice@example.test", false)
}
