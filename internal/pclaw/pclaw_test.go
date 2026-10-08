// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

func envOf(m map[string]string) Env {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestCheckServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://pc.example.com": "https://pc.example.com", "https://pc.example.com/": "https://pc.example.com",
		"http://127.0.0.1:8080": "http://127.0.0.1:8080", "http://localhost:8080": "http://localhost:8080",
	} {
		if got, err := checkServer(in); err != nil || got != want {
			t.Errorf("checkServer(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "pc.example.com", "http://pc.example.com", "https://u:p@pc.example.com", "https://pc.example.com/x", "ftp://pc"} {
		if _, err := checkServer(bad); err == nil {
			t.Errorf("checkServer(%q) accepted", bad)
		}
	}
}

func TestCredentialsFileIsPrivateAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	if _, err := loadCreds(env); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("empty dir: %v", err)
	}
	c := Credentials{
		Server: "https://pc.example.com", Org: "o", AccessToken: "a", RefreshToken: "r", DeviceKey: "k",
		AccessExpiry: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
	}
	if err := saveCreds(env, c); err != nil {
		t.Fatal(err)
	}
	got, err := loadCreds(env)
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "credentials.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("credentials mode %v", fi.Mode().Perm())
		}
	}
	if err := deleteCreds(env); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCreds(env); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after delete: %v", err)
	}
}

// fakeServer implements just enough of the OAuth endpoints and WhoAmI.
type fakeServer struct {
	*httptest.Server
	polls    atomic.Int32
	outcome  string // after two pending polls: "ok", "denied"
	refresh  string // "ok" or "invalid_grant"
	lastAuth atomic.Value
	link     string // override verification_uri_complete
}

type fakeAccess struct {
	pantherclawv1connect.UnimplementedAccessServiceHandler
	f *fakeServer
}

func (w fakeAccess) WhoAmI(ctx context.Context, _ *pantherclawv1.WhoAmIRequest) (*pantherclawv1.WhoAmIResponse, error) {
	return &pantherclawv1.WhoAmIResponse{
		OrgName: "acme", OrgId: "org-1", Credential: "access_token",
		Principal: &pantherclawv1.Principal{DisplayName: "me@acme.test"},
	}, nil
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{outcome: "ok", refresh: "ok"}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.MarshalWrite(w, v)
	}
	mux.HandleFunc("POST /oauth2/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, err := assertion.ParsePublicJWK(assertion.EdDSA, []byte(r.PostForm.Get("device_jwk"))); err != nil || r.PostForm.Get("org") == "" {
			write(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		link := f.URL + "/device?org=o&user_code=BCDF-GHJK"
		if f.link != "" {
			link = f.link
		}
		write(w, 200, map[string]any{
			"device_code": "pcd_x", "user_code": "BCDF-GHJK", "verification_uri": f.URL + "/device",
			"verification_uri_complete": link, "expires_in": 30, "interval": 0,
		})
	})
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("client_assertion") == "" || r.PostForm.Get("client_id") != "pclaw" {
			write(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			if f.refresh != "ok" {
				write(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
			write(w, 200, map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 900, "refresh_token": "pcr_2"})
		default:
			n := f.polls.Add(1)
			switch {
			case n == 1:
				write(w, 400, map[string]string{"error": "authorization_pending"})
			case n == 2:
				write(w, 400, map[string]string{"error": "slow_down"})
			case f.outcome == "denied":
				write(w, 400, map[string]string{"error": "access_denied"})
			default:
				write(w, 200, map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 900, "refresh_token": "pcr_1"})
			}
		}
	})
	mux.HandleFunc("POST /oauth2/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAccessServiceHandler(cs, fakeAccess{f: f})
	rpcMux := http.NewServeMux()
	connecthttp.Mount(rpcMux, cs)
	path, h := "/"+pantherclawv1connect.AccessServiceName+"/", http.Handler(rpcMux)
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth.Store(r.Header.Get("Authorization"))
		h.ServeHTTP(w, r)
	}))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func run(t *testing.T, env Env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	opened := ""
	code := Run(context.Background(), args, &out, &errb, env, Options{OpenBrowser: func(_ context.Context, u string) error { opened = u; return nil }})
	if opened != "" && !strings.Contains(out.String(), opened) {
		t.Errorf("opened %q, which was not printed", opened)
	}
	return code, out.String(), errb.String()
}

func TestLoginPollsStoresAndRefreshes(t *testing.T) {
	f := newFake(t)
	dir := t.TempDir()
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": dir})
	code, out, errs := run(t, env, "login", "--server", f.URL, "--org", "o")
	if code != 0 || !strings.Contains(out, "BCDF-GHJK") || !strings.Contains(out, "me@acme.test") {
		t.Fatalf("login = %d\n%s\n%s", code, out, errs)
	}
	c, err := loadCreds(env)
	if err != nil || c.AccessToken != "at-1" || c.RefreshToken != "pcr_1" || c.Org != "o" {
		t.Fatalf("stored %+v %v", c, err)
	}
	if _, err := c.deviceKey(); err != nil {
		t.Fatal(err)
	}
	// An almost expired access token is refreshed (signed with the device
	// key) and the rotated tokens are saved.
	c.AccessExpiry = time.Now().Add(10 * time.Second)
	if err := saveCreds(env, c); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := run(t, env, "whoami"); code != 0 || f.lastAuth.Load() != "Bearer at-2" {
		t.Fatalf("whoami after expiry = %d %q %q auth=%v", code, out, errs, f.lastAuth.Load())
	}
	if c2, _ := loadCreds(env); c2.RefreshToken != "pcr_2" {
		t.Fatalf("rotated refresh token not saved: %+v", c2)
	}
	// A revoked session tells the user to log in again.
	f.refresh = "invalid_grant"
	c2, _ := loadCreds(env)
	c2.AccessExpiry = time.Now()
	_ = saveCreds(env, c2)
	if code, _, errs := run(t, env, "whoami"); code != 1 || !strings.Contains(errs, "pclaw login") {
		t.Fatalf("ended session = %d %q", code, errs)
	}
	if code, out, _ := run(t, env, "logout"); code != 0 || !strings.Contains(out, "logged out") {
		t.Fatalf("logout = %d %q", code, out)
	}
	if _, err := loadCreds(env); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("credentials kept after logout: %v", err)
	}
}

func TestLoginRefusesForeignLinksAndReportsDenial(t *testing.T) {
	f := newFake(t)
	env := envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir()})
	f.link = "https://evil.test/device"
	if code, _, errs := run(t, env, "login", "--server", f.URL, "--org", "o"); code != 1 || !strings.Contains(errs, "another site") {
		t.Fatalf("foreign link: %d %q", code, errs)
	}
	f.link, f.outcome = "", "denied"
	if code, _, errs := run(t, env, "login", "--server", f.URL, "--org", "o", "--no-browser"); code != 1 || !strings.Contains(errs, "denied") {
		t.Fatalf("denied: %d %q", code, errs)
	}
}

func TestAPIKeyFromEnvironment(t *testing.T) {
	f := newFake(t)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": f.URL, "PANTHERCLAW_API_KEY": "pck_test_x", "PANTHERCLAW_CONFIG_DIR": t.TempDir()})
	if code, out, errs := run(t, env, "whoami"); code != 0 || f.lastAuth.Load() != "Bearer pck_test_x" {
		t.Fatalf("whoami with API key = %d %q %q", code, out, errs)
	}
	env = envOf(map[string]string{"PANTHERCLAW_SERVER": "http://pc.example.com", "PANTHERCLAW_API_KEY": "pck_test_x"})
	if code, _, errs := run(t, env, "whoami"); code != 1 || !strings.Contains(errs, "https") {
		t.Fatalf("API key over plain http: %d %q", code, errs)
	}
}

func TestUsage(t *testing.T) {
	env := envOf(nil)
	if code, _, errs := run(t, env); code != 2 || !strings.Contains(errs, "pclaw login") {
		t.Fatalf("no args: %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "frobnicate"); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	if code, _, _ := run(t, env, "login", "--org", "o"); code != 2 {
		t.Fatalf("login without server: %d", code)
	}
	if code, out, _ := run(t, env, "version"); code != 0 || !strings.Contains(out, "pclaw") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, errs := run(t, envOf(map[string]string{"PANTHERCLAW_CONFIG_DIR": t.TempDir()}), "whoami"); code != 1 || !strings.Contains(errs, "not logged in") {
		t.Fatalf("whoami logged out: %d %q", code, errs)
	}
}

func init() { minPollInterval, slowDownStep = 5*time.Millisecond, 5*time.Millisecond }
