// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const rpID = "pc.example.test" // the host of browserIssuer

// notices records security notices.
type notices struct {
	mu   sync.Mutex
	list []authnapp.SecurityNotice
}

func (n *notices) SecurityNotice(_ context.Context, _ db.TenantTx, x authnapp.SecurityNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.list = append(n.list, x)
	return nil
}

func (n *notices) types() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, x := range n.list {
		out = append(out, x.Type)
	}
	return out
}

type waEnv struct {
	*browserEnv
	wa      *authnapp.WebAuthn
	notices *notices
}

func newWAEnv(t *testing.T) *waEnv {
	t.Helper()
	b := newBrowserEnv(t)
	n := &notices{}
	wa, err := authnapp.NewWebAuthn(b.pool, authnapp.WebAuthnConfig{RPID: rpID, PublicURL: browserIssuer}, n, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &waEnv{browserEnv: b, wa: wa, notices: n}
}

// session signs in (recent: with max_age) and authenticates the cookie.
func (e *waEnv) session(t *testing.T, recent bool) (authnapp.BrowserSession, string) {
	t.Helper()
	out := e.signIn(t, recent)
	if out.Reason != "" {
		t.Fatalf("sign-in refused: %s", out.Reason)
	}
	s, err := e.browser.Authenticate(context.Background(), out.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return s, out.Secret
}

func (e *waEnv) authenticator(t *testing.T, alg webauthntest.Alg) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(browserIssuer, rpID, alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// register adds a's key to the session's user.
func (e *waEnv) register(t *testing.T, s authnapp.BrowserSession, a *webauthntest.Authenticator, name string) (authnapp.CredentialInfo, error) {
	t.Helper()
	c, err := e.wa.BeginRegistration(context.Background(), s)
	if err != nil {
		return authnapp.CredentialInfo{}, err
	}
	resp, err := a.Register(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	return e.wa.FinishRegistration(context.Background(), s, c.ID, name, resp)
}

func (e *waEnv) stepUp(t *testing.T, s authnapp.BrowserSession, a *webauthntest.Authenticator) (authnapp.StepUp, error) {
	t.Helper()
	c, err := e.wa.BeginStepUp(context.Background(), s)
	if err != nil {
		return authnapp.StepUp{}, err
	}
	resp, err := a.Assert(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	return e.wa.FinishStepUp(context.Background(), s, c.ID, resp)
}

// reauth re-reads the session (after a step-up or an aged auth_time).
func (e *waEnv) reauth(t *testing.T, secret string) authnapp.BrowserSession {
	t.Helper()
	s, err := e.browser.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHR155_AddingAndRemovingKeysNeedRecentStrongAuthentication(t *testing.T) {
	e := newWAEnv(t)
	ctx := context.Background()
	stale, _ := e.session(t, false)
	if _, err := e.wa.BeginRegistration(ctx, stale); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
		t.Fatalf("first key without a recent sign-in: %v", err)
	}
	s, secret := e.session(t, true)
	first := e.authenticator(t, webauthntest.ES256)
	key, err := e.register(t, s, first, "YubiKey")
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm != -7 || key.State != "ACTIVE" {
		t.Fatalf("registered %+v", key)
	}
	// Ten minutes later the provider sign-in no longer counts.
	e.d.AdminExec(t, "UPDATE pc.sessions SET auth_time = now() - interval '10 minutes'")
	s = e.reauth(t, secret)
	second := e.authenticator(t, webauthntest.EdDSA)
	if _, err := e.register(t, s, second, "Laptop"); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
		t.Fatalf("second key with a stale sign-in: %v", err)
	}
	if err := e.wa.RemoveCredential(ctx, s, key.ID); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
		t.Fatalf("removal with a stale sign-in: %v", err)
	}
	// A step-up with the existing key is recent strong authentication.
	up, err := e.stepUp(t, s, first)
	if err != nil {
		t.Fatal(err)
	}
	s = e.reauth(t, up.Rotated)
	laptop, err := e.register(t, s, second, "Laptop")
	if err != nil {
		t.Fatalf("second key after a step-up: %v", err)
	}
	if err := e.wa.RemoveCredential(ctx, s, laptop.ID); err != nil {
		t.Fatalf("removal after a step-up: %v", err)
	}
	if err := e.wa.RemoveCredential(ctx, s, laptop.ID); !errors.Is(err, authnapp.ErrCredentialNotFound) {
		t.Fatalf("removing twice: %v", err)
	}
	want := []string{"security.credential_registered", "security.credential_registered", "security.credential_removed"}
	if got := e.notices.types(); len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("notices %v, want %v", got, want)
	}
	for _, kind := range []string{"audit.authn.webauthn_registered", "audit.authn.webauthn_removed", "audit.authn.step_up"} {
		if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = $1", kind); n == 0 {
			t.Errorf("no %s audit event", kind)
		}
	}
	// A step-up with a key that was removed since does not count.
	e.d.AdminExec(t, "UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now() WHERE id = $1", key.ID)
	s = e.reauth(t, up.Rotated)
	if _, err := e.wa.BeginRegistration(ctx, s); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
		t.Fatalf("step-up with a removed key still counts: %v", err)
	}
}

func TestHR153_CeremoniesPinOriginRPAndUserVerification(t *testing.T) {
	e := newWAEnv(t)
	ctx := context.Background()
	s, _ := e.session(t, true)
	for name, knob := range map[string]func(*webauthntest.Authenticator){
		"another origin":                   func(a *webauthntest.Authenticator) { a.Origin = "https://evil.example" },
		"a subdomain origin":               func(a *webauthntest.Authenticator) { a.Origin = "https://login.pc.example.test" },
		"another RP id":                    func(a *webauthntest.Authenticator) { a.RPID = "evil.example" },
		"no user verification":             func(a *webauthntest.Authenticator) { a.NoUV = true },
		"backup state without eligibility": func(a *webauthntest.Authenticator) { a.BackupState = true },
	} {
		a := e.authenticator(t, webauthntest.ES256)
		knob(a)
		if _, err := e.register(t, s, a, "key"); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
			t.Errorf("%s: %v, want ErrWebAuthnFailed", name, err)
		}
	}
	if _, err := e.register(t, s, e.authenticator(t, webauthntest.RS1024), "weak"); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
		t.Errorf("1,024-bit RSA key: %v", err)
	}
	if _, err := e.register(t, s, e.authenticator(t, webauthntest.RS256), "hello"); err != nil {
		t.Errorf("2,048-bit RSA key (Windows Hello): %v", err)
	}

	// A ceremony works once, for its own session and user, before it expires.
	a := e.authenticator(t, webauthntest.ES256)
	c, err := e.wa.BeginRegistration(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := a.Register(c.Options)
	other, _ := e.session(t, true)
	if _, err := e.wa.FinishRegistration(ctx, other, c.ID, "key", resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Errorf("another session's ceremony: %v", err)
	}
	if _, err := e.wa.FinishRegistration(ctx, s, c.ID, "key", resp); err != nil {
		t.Fatalf("own ceremony: %v", err)
	}
	if _, err := e.wa.FinishRegistration(ctx, s, c.ID, "key", resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Errorf("reused ceremony: %v", err)
	}
	// The same authenticator again: its credential id already exists in the org.
	if _, err := e.register(t, s, a, "again"); !errors.Is(err, authnapp.ErrCredentialExists) {
		t.Errorf("registered twice: %v", err)
	}
	c, err = e.wa.BeginStepUp(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	e.d.AdminExec(t, "UPDATE pc.webauthn_ceremonies SET expires_at = now() - interval '1 second' WHERE id = $1", c.ID)
	resp, _ = a.Assert(c.Options)
	if _, err := e.wa.FinishStepUp(ctx, s, c.ID, resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Errorf("expired ceremony: %v", err)
	}
	// A registration ceremony cannot finish a step-up.
	c, err = e.wa.BeginRegistration(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.wa.FinishStepUp(ctx, s, c.ID, resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Errorf("registration ceremony used for a step-up: %v", err)
	}
	if _, err := e.wa.FinishRegistration(ctx, s, ids.NewV7(), "key", []byte(`{"not":"webauthn"}`)); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
		t.Errorf("unknown ceremony: %v", err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.webauthn_credentials"); n != 2 {
		t.Errorf("%d credentials stored, want 2 (RS256 and ES256)", n)
	}
}

func TestHR154_ACounterThatDoesNotMoveSuspendsTheKey(t *testing.T) {
	e := newWAEnv(t)
	s, _ := e.session(t, true)
	a := e.authenticator(t, webauthntest.ES256)
	key, err := e.register(t, s, a, "key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.stepUp(t, s, a); err != nil { // counter 1
		t.Fatal(err)
	}
	if _, err := e.stepUp(t, s, a); err != nil { // counter 2
		t.Fatal(err)
	}
	a.Counter = 2 // a clone that used the same value
	if _, err := e.stepUp(t, s, a); !errors.Is(err, authnapp.ErrCredentialSuspended) {
		t.Fatalf("repeated counter: %v", err)
	}
	keys, err := e.wa.ListCredentials(context.Background(), s)
	if err != nil || len(keys) != 1 || keys[0].ID != key.ID || keys[0].State != "SUSPENDED" || keys[0].StateReason != "CLONE_SUSPECTED" {
		t.Fatalf("after the regression: %+v %v", keys, err)
	}
	if got := e.notices.types(); got[len(got)-1] != "security.credential_suspended" {
		t.Errorf("notices %v", got)
	}
	if _, err := e.stepUp(t, s, a); !errors.Is(err, authnapp.ErrNoCredentials) {
		t.Errorf("step-up with a suspended key: %v", err)
	}

	// A synced passkey reports 0 every time, and that is fine.
	p := e.authenticator(t, webauthntest.ES256)
	p.ZeroCounter, p.BackupEligible, p.BackupState = true, true, true
	s, _ = e.session(t, true)
	if _, err := e.register(t, s, p, "passkey"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := e.stepUp(t, s, p); err != nil {
			t.Fatalf("synced passkey: %v", err)
		}
	}
	// Its backup-eligible flag cannot change afterwards.
	p.BackupEligible, p.BackupState = false, false
	if _, err := e.stepUp(t, s, p); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
		t.Errorf("changed backup eligibility: %v", err)
	}
}

func TestHR156_StepUpBelongsToOneSessionForFiveMinutes(t *testing.T) {
	e := newWAEnv(t)
	ctx := context.Background()
	s, secret := e.session(t, true)
	other, otherSecret := e.session(t, true)
	a := e.authenticator(t, webauthntest.ES256)
	if _, err := e.register(t, s, a, "key"); err != nil {
		t.Fatal(err)
	}
	up, err := e.stepUp(t, s, a)
	if err != nil {
		t.Fatal(err)
	}
	if up.Rotated == "" || up.Rotated == secret {
		t.Fatal("step-up did not rotate the session secret")
	}
	if s := e.reauth(t, up.Rotated); !s.SteppedUpWithin(authnapp.StepUpLifetime) || s.StepUpCredential != up.Credential {
		t.Fatalf("stepped-up session %+v", s)
	}
	if o := e.reauth(t, otherSecret); o.SteppedUpWithin(authnapp.StepUpLifetime) {
		t.Fatal("another session of the same user is stepped up")
	}
	_ = other
	e.d.AdminExec(t, "UPDATE pc.sessions SET step_up_at = now() - interval '6 minutes' WHERE id = $1", s.ID)
	if s := e.reauth(t, up.Rotated); s.SteppedUpWithin(authnapp.StepUpLifetime) {
		t.Fatal("a 6-minute-old step-up still counts")
	}
	// A user without keys cannot step up.
	if _, err := e.wa.BeginStepUp(ctx, other); err != nil {
		t.Fatalf("the user has a key: %v", err)
	}
	e.d.AdminExec(t, "UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()")
	if _, err := e.wa.BeginStepUp(ctx, other); !errors.Is(err, authnapp.ErrNoCredentials) {
		t.Fatalf("no keys: %v", err)
	}
}

func TestHR153_RenamingAndListingAreOwnKeysOnly(t *testing.T) {
	e := newWAEnv(t)
	ctx := context.Background()
	s, _ := e.session(t, true)
	key, err := e.register(t, s, e.authenticator(t, webauthntest.ES256), "key")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.wa.RenameCredential(ctx, s, key.ID, "Desk key"); err != nil {
		t.Fatal(err)
	}
	if err := e.wa.RenameCredential(ctx, s, key.ID, "bad"+string(rune(0x202e))+"name"); !errors.Is(err, authnapp.ErrBadCredentialName) {
		t.Errorf("bidi name: %v", err)
	}
	// Bob's key is not Alice's to rename or remove (IDOR).
	bob := ids.NewV7()
	bobKey := ids.NewV7()
	e.exec(t, e.org, `INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')`, e.org, bob)
	e.exec(t, e.org, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'bob')`,
		e.org, bobKey, bob, sum32(1), append(sum32(2), sum32(3)...))
	if err := e.wa.RenameCredential(ctx, s, bobKey, "mine"); !errors.Is(err, authnapp.ErrCredentialNotFound) {
		t.Errorf("rename another user's key: %v", err)
	}
	if err := e.wa.RemoveCredential(ctx, s, bobKey); !errors.Is(err, authnapp.ErrCredentialNotFound) {
		t.Errorf("remove another user's key: %v", err)
	}
	keys, err := e.wa.ListCredentials(ctx, s)
	if err != nil || len(keys) != 1 || keys[0].Name != "Desk key" {
		t.Fatalf("own keys %+v %v", keys, err)
	}
}
