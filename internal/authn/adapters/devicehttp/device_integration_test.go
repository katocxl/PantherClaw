// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package devicehttp_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/devicehttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
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

type env struct {
	pool   *db.Pool
	idp    *oidctest.Provider
	issuer string
	authn  *authnapp.Authenticator
}

func newEnv(t *testing.T, trustEmail bool) *env {
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
		AllowInsecureLoopback: true, TrustEmail: trustEmail, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := httpx.NewLimiter(10000, time.Minute, nil)
	oauth := oauthhttp.New(authnapp.NewOAuth(pool, tokens, issuer, clock.System{}, nil), issuer, limiter)
	oauth.Mount(mux)
	dev, err := devicehttp.New(authnapp.NewDevice(pool, tokens, issuer, []authnapp.IdP{prov}, clock.System{}, nil), issuer, limiter, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev.Mount(mux, oauth)
	ts.Start()
	t.Cleanup(ts.Close)
	a, err := authnapp.NewAuthenticator(pool, tokens, credential.EnvTest, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{pool: pool, idp: idp, issuer: issuer, authn: a}
}

func (e *env) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) count(t *testing.T, org ids.OrgID, sql string, args ...any) int {
	t.Helper()
	var n int
	err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) org(t *testing.T) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	e.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	return org
}

// invite stores an invitation and returns its token.
func (e *env) invite(t *testing.T, org ids.OrgID, kind, email string, roles []string, ttl string) string {
	t.Helper()
	tok, _ := credential.New(credential.Invitation, "", org)
	if roles == nil {
		roles = []string{}
	}
	e.exec(t, org, `INSERT INTO pc.invitations (org_id, id, kind, email, roles, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'operator:test', now() + $7::interval)`, org, ids.NewV7(), kind, email, roles, tok.Hash(), ttl)
	return tok.Reveal()
}

func (e *env) user(t *testing.T, org ids.OrgID, sub, email, state string) {
	t.Helper()
	e.exec(t, org, `INSERT INTO pc.users (org_id, id, issuer, subject, email, state) VALUES ($1, $2, $3, $4, $5, $6)`,
		org, ids.NewV7(), e.idp.Issuer(), sub, email, state)
}

// cli is a pclaw with its device key.
type cli struct {
	priv ed25519.PrivateKey
	jwk  string
	kid  string
}

func newCLI(t *testing.T) cli {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := jose.JSONWebKey{Key: pub}.MarshalJSON()
	pk, err := assertion.ParsePublicJWK(assertion.EdDSA, raw)
	if err != nil {
		t.Fatal(err)
	}
	return cli{priv: priv, jwk: string(raw), kid: pk.Thumbprint}
}

func (c cli) assertion(t *testing.T, aud string) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{
		"iss": authnapp.CLIClientID, "sub": authnapp.CLIClientID, "aud": aud, "jti": ids.NewV7().String(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.priv}, (&jose.SignerOptions{}).WithHeader("kid", c.kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, _ := s.Sign(claims)
	out, _ := obj.CompactSerialize()
	return out
}

func noRedirects() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// reply is a read and closed HTTP response.
type reply struct {
	StatusCode int
	Header     http.Header
}

func do(t *testing.T, c *http.Client, method, u string, form url.Values, hdr map[string]string) (reply, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return reply{StatusCode: res.StatusCode, Header: res.Header}, string(b)
}

func (e *env) start(t *testing.T, c cli, org ids.OrgID, invitation string) (authnapp.DeviceAuthorization, int) {
	t.Helper()
	res, body := do(t, noRedirects(), http.MethodPost, e.issuer+authnapp.DeviceAuthorizationPath, url.Values{
		"client_id": {authnapp.CLIClientID}, "org": {org.String()}, "device_jwk": {c.jwk}, "device_name": {"laptop\u0007"},
		"invitation": {invitation},
	}, nil)
	var da authnapp.DeviceAuthorization
	_ = json.Unmarshal([]byte(body), &da)
	return da, res.StatusCode
}

// browser signs the person in through the confirmation page and the
// provider, and returns the result page.
func (e *env) browser(t *testing.T, da authnapp.DeviceAuthorization, keepCookie bool) (int, string, string) {
	t.Helper()
	b := noRedirects()
	res, page := do(t, b, http.MethodGet, da.VerificationURIComplete, nil, nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, da.UserCode) {
		t.Fatalf("confirmation page %d: %s", res.StatusCode, page)
	}
	u, _ := url.Parse(da.VerificationURIComplete)
	res, _ = do(t, b, http.MethodPost, e.issuer+authnapp.DevicePath, url.Values{
		"org": {u.Query().Get("org")}, "user_code": {da.UserCode},
	}, map[string]string{"Origin": e.issuer})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm: %d", res.StatusCode)
	}
	res, _ = do(t, b, http.MethodGet, res.Header.Get("Location"), nil, nil) // the provider signs in at once
	callback := res.Header.Get("Location")
	if !strings.HasPrefix(callback, e.issuer+authnapp.CallbackPath+"test?") {
		t.Fatalf("provider redirected to %q", callback)
	}
	if !keepCookie {
		b.Jar, _ = cookiejar.New(nil)
	}
	res, page = do(t, b, http.MethodGet, callback, nil, nil)
	return res.StatusCode, page, callback
}

func (e *env) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	res, body := do(t, noRedirects(), http.MethodPost, e.issuer+authnapp.TokenPath, form, nil)
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return res.StatusCode, m
}

func (e *env) poll(t *testing.T, c cli, deviceCode string) (int, map[string]any) {
	t.Helper()
	return e.token(t, url.Values{
		"grant_type": {oauthhttp.GrantDeviceCode}, "device_code": {deviceCode}, "client_id": {authnapp.CLIClientID},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {c.assertion(t, e.issuer+authnapp.TokenPath)},
	})
}

func (e *env) refresh(t *testing.T, c cli, rt string) (int, map[string]any) {
	t.Helper()
	return e.token(t, url.Values{
		"grant_type": {oauthhttp.GrantRefreshToken}, "refresh_token": {rt}, "client_id": {authnapp.CLIClientID},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {c.assertion(t, e.issuer)},
	})
}

func TestIntDeviceLoginBootstrapRefreshAndReuse(t *testing.T) {
	e := newEnv(t, false)
	org := e.org(t)
	inv := e.invite(t, org, "BOOTSTRAP", "", []string{"org_admin"}, "24 hours")
	c := newCLI(t)
	da, status := e.start(t, c, org, inv)
	if status != http.StatusOK || da.Interval != 5 || da.ExpiresIn != 600 || !strings.HasPrefix(da.DeviceCode, "pcd_") {
		t.Fatalf("device authorization %d %+v", status, da)
	}
	if st, m := e.poll(t, c, da.DeviceCode); st != 400 || m["error"] != "authorization_pending" {
		t.Fatalf("before sign-in: %d %v", st, m)
	}
	if st, m := e.poll(t, c, da.DeviceCode); st != 400 || m["error"] != "slow_down" {
		t.Fatalf("polling too fast: %d %v", st, m)
	}
	st, page, _ := e.browser(t, da, true)
	if st != http.StatusOK || !strings.Contains(page, "You are signed in") || !strings.Contains(page, "user1@example.test") {
		t.Fatalf("result %d: %s", st, page)
	}
	e.exec(t, org, "UPDATE pc.device_codes SET last_polled_at = NULL") // skip the poll interval
	st, tok := e.poll(t, c, da.DeviceCode)
	if st != 200 || tok["token_type"] != "Bearer" || !strings.HasPrefix(tok["refresh_token"].(string), "pcr_") {
		t.Fatalf("device-code grant: %d %v", st, tok)
	}
	caller, err := e.authn.Authenticate(context.Background(), tok["access_token"].(string))
	if err != nil || !caller.CanAnywhere("role.bind") {
		t.Fatalf("bootstrap admin token: %+v %v", caller, err)
	}
	if n := e.count(t, org, "SELECT count(*) FROM pc.invitations WHERE state = 'ACCEPTED'"); n != 1 {
		t.Fatalf("invitation not accepted")
	}
	if n := e.count(t, org, "SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.authn.login', 'audit.access.user_created', 'audit.access.invitation_accepted', 'audit.authn.session_created')"); n != 4 {
		t.Fatalf("audit entries = %d", n)
	}
	if n := e.count(t, org, "SELECT count(*) FROM pc.device_codes WHERE nonce IS NOT NULL OR pkce_verifier IS NOT NULL"); n != 0 {
		t.Fatal("nonce or PKCE verifier kept after the callback")
	}
	e.exec(t, org, "UPDATE pc.device_codes SET last_polled_at = NULL")
	if st, m := e.poll(t, c, da.DeviceCode); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("device code reused: %d %v", st, m)
	}
	// A second CLI cannot use the refresh token: it must be signed with this device key.
	if st, m := e.refresh(t, newCLI(t), tok["refresh_token"].(string)); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("refresh with another device key: %d %v", st, m)
	}
	st, r1 := e.refresh(t, c, tok["refresh_token"].(string))
	if st != 200 || r1["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh: %d %v", st, r1)
	}
	// Reusing the rotated refresh token revokes the whole session.
	if st, m := e.refresh(t, c, tok["refresh_token"].(string)); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("refresh reuse: %d %v", st, m)
	}
	if _, err := e.authn.Authenticate(context.Background(), r1["access_token"].(string)); err == nil {
		t.Fatal("session survived refresh-token reuse")
	}
	if st, m := e.refresh(t, c, r1["refresh_token"].(string)); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("refresh after revocation: %d %v", st, m)
	}
}

func TestIntDeviceLoginLogoutRevokes(t *testing.T) {
	e := newEnv(t, false)
	org := e.org(t)
	e.user(t, org, "user-1", "user1@example.test", "ACTIVE")
	c := newCLI(t)
	da, _ := e.start(t, c, org, "")
	if st, page, _ := e.browser(t, da, true); st != 200 {
		t.Fatalf("login: %d %s", st, page)
	}
	_, tok := e.poll(t, c, da.DeviceCode)
	res, _ := do(t, noRedirects(), http.MethodPost, e.issuer+authnapp.RevocationPath, url.Values{"token": {tok["refresh_token"].(string)}}, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	if _, err := e.authn.Authenticate(context.Background(), tok["access_token"].(string)); err == nil {
		t.Fatal("access token works after logout")
	}
	if res, _ := do(t, noRedirects(), http.MethodPost, e.issuer+authnapp.RevocationPath, url.Values{"token": {"pcr_garbage"}}, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("revoking an unknown token: %d", res.StatusCode)
	}
}

// loginWith runs a whole login with the provider misbehaving as k and
// returns the result page status and the device grant error.
func (e *env) loginWith(t *testing.T, org ids.OrgID, k oidctest.Knobs, invitation string) (int, string, any) {
	t.Helper()
	e.idp.Set(k)
	defer e.idp.Set(oidctest.Knobs{})
	c := newCLI(t)
	da, st := e.start(t, c, org, invitation)
	if st != 200 {
		t.Fatalf("start: %d", st)
	}
	st, page, _ := e.browser(t, da, true)
	_, m := e.poll(t, c, da.DeviceCode)
	return st, page, m["error"]
}

// TestT032_IDTokensAreVerified: forged, misaddressed, replayed or stale ID
// tokens never sign anyone in, and the waiting CLI is told access_denied.
func TestT032_IDTokensAreVerified(t *testing.T) {
	e := newEnv(t, false)
	org := e.org(t)
	e.user(t, org, "user-1", "user1@example.test", "ACTIVE")
	for name, k := range map[string]oidctest.Knobs{
		"alg none":          {Alg: "none"},
		"HS256 with RSA N":  {Alg: "HS256"},
		"other audience":    {Audience: []string{"another-client"}},
		"other issuer":      {Issuer: "https://evil.test"},
		"wrong nonce":       {Nonce: "replayed-nonce"},
		"expired":           {Expired: true},
		"azp other client":  {Audience: []string{"pantherclaw", "other"}, AZP: "other"},
		"extra aud, no azp": {Audience: []string{"pantherclaw", "other"}},
	} {
		st, page, grantErr := e.loginWith(t, org, k, "")
		if st != http.StatusForbidden || !strings.Contains(page, "could not be verified") || grantErr != "access_denied" {
			t.Errorf("%s: page %d, grant %v", name, st, grantErr)
		}
	}
}

// TestT037_OIDCMixUpAndLoginCSRF: an authorization response carrying
// another issuer, or none when the provider advertises RFC 9207, is
// refused; a callback without the confirming browser's cookie is refused and
// burns the state; a callback cannot be replayed; the confirmation cannot be
// posted cross-site.
func TestT037_OIDCMixUpAndLoginCSRF(t *testing.T) {
	e := newEnv(t, false)
	org := e.org(t)
	e.user(t, org, "user-1", "user1@example.test", "ACTIVE")
	for name, k := range map[string]oidctest.Knobs{
		"iss of another provider":  {WrongIssParam: "https://other-idp.test"},
		"iss missing (advertised)": {OmitIssParam: true},
		"provider error":           {Error: "access_denied"},
	} {
		if st, _, grantErr := e.loginWith(t, org, k, ""); st != http.StatusForbidden || grantErr != "access_denied" {
			t.Errorf("%s: page %d, grant %v", name, st, grantErr)
		}
	}
	// A provider that does not advertise RFC 9207 (metadata is read once,
	// so it needs its own provider) may omit iss; the per-provider callback
	// URL is then the mix-up defense.
	e2 := newEnv(t, false)
	e2.idp.Set(oidctest.Knobs{OmitIssParam: true, NoIssSupport: true})
	org2 := e2.org(t)
	e2.user(t, org2, "user-1", "user1@example.test", "ACTIVE")
	if st, _, grantErr := e2.loginWith(t, org2, oidctest.Knobs{OmitIssParam: true, NoIssSupport: true}, ""); st != 200 || grantErr != nil {
		t.Errorf("iss missing, not advertised: page %d, grant %v", st, grantErr)
	}

	c := newCLI(t)
	da, _ := e.start(t, c, org, "")
	st, _, callback := e.browser(t, da, false) // the cookie is lost: another browser
	if st != http.StatusForbidden {
		t.Errorf("callback without binding cookie: %d", st)
	}
	if res, _ := do(t, noRedirects(), http.MethodGet, callback, nil, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("replayed callback: %d", res.StatusCode)
	}
	if _, m := e.poll(t, c, da.DeviceCode); m["error"] != "access_denied" {
		t.Errorf("device after failed binding: %v", m)
	}

	da, _ = e.start(t, newCLI(t), org, "")
	u, _ := url.Parse(da.VerificationURIComplete)
	form := url.Values{"org": {u.Query().Get("org")}, "user_code": {da.UserCode}}
	for name, hdr := range map[string]map[string]string{
		"other origin":         {"Origin": "https://evil.test"},
		"cross-site fetch":     {"Sec-Fetch-Site": "cross-site"},
		"no origin, no fetch":  {},
		"null origin (iframe)": {"Origin": "null"},
	} {
		if res, _ := do(t, noRedirects(), http.MethodPost, e.issuer+authnapp.DevicePath, form, hdr); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: confirm %d", name, res.StatusCode)
		}
	}
	if res, _ := do(t, noRedirects(), http.MethodGet, e.issuer+authnapp.DevicePath+"?org="+org.String()+"&user_code=BBBB-BBBB", nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown user code: %d", res.StatusCode)
	}
}

func TestIntDeviceLoginMembershipAndInvitations(t *testing.T) {
	e := newEnv(t, false)
	org := e.org(t)
	if st, page, grantErr := e.loginWith(t, org, oidctest.Knobs{}, ""); st != 403 || !strings.Contains(page, "not a member") || grantErr != "access_denied" {
		t.Errorf("stranger: %d %v", st, grantErr)
	}
	e.idp.SignIn(oidctest.User{Subject: "bob", Email: "bob@example.test", EmailVerified: true})
	if st, _, _ := e.loginWith(t, org, oidctest.Knobs{}, e.invite(t, org, "MEMBER", "alice@example.test", []string{"viewer"}, "1 day")); st != 403 {
		t.Errorf("invitation for another email: %d", st)
	}
	e.idp.SignIn(oidctest.User{Subject: "carol", Email: "carol@example.test", EmailVerified: false})
	if st, _, _ := e.loginWith(t, org, oidctest.Knobs{}, e.invite(t, org, "MEMBER", "carol@example.test", nil, "1 day")); st != 403 {
		t.Errorf("unverified email: %d", st)
	}
	e.idp.SignIn(oidctest.User{Subject: "dave", Email: "Dave@Example.TEST", EmailVerified: true})
	if st, page, grantErr := e.loginWith(t, org, oidctest.Knobs{}, e.invite(t, org, "MEMBER", "dave@example.test", []string{"viewer"}, "1 day")); st != 200 || grantErr != nil {
		t.Errorf("invited member: %d %v %s", st, grantErr, page)
	}
	if n := e.count(t, org, "SELECT count(*) FROM pc.role_bindings rb JOIN pc.users u ON u.id = rb.user_id WHERE u.subject = 'dave' AND rb.role = 'viewer'"); n != 1 {
		t.Errorf("invited roles not granted")
	}
	e.user(t, org, "erin", "erin@example.test", "DISABLED")
	e.idp.SignIn(oidctest.User{Subject: "erin", Email: "erin@example.test", EmailVerified: true})
	if st, page, _ := e.loginWith(t, org, oidctest.Knobs{}, ""); st != 403 || !strings.Contains(page, "disabled") {
		t.Errorf("disabled user: %d", st)
	}
	// An expired or foreign invitation cannot even start a login.
	if _, st := e.start(t, newCLI(t), org, e.invite(t, org, "MEMBER", "x@example.test", nil, "-1 hour")); st != 400 {
		t.Errorf("expired invitation: %d", st)
	}
	other := e.org(t)
	if _, st := e.start(t, newCLI(t), org, e.invite(t, other, "MEMBER", "x@example.test", nil, "1 day")); st != 400 {
		t.Errorf("invitation of another org: %d", st)
	}
	if _, st := e.start(t, newCLI(t), ids.New[ids.Org](), ""); st != 400 {
		t.Errorf("unknown org: %d", st)
	}
}
