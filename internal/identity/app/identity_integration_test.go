// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	issuer    = "https://pc.example.test"
	enrollURL = issuer + "/pantherclaw.v1.WorkloadService/Enroll"
	tokenURL  = issuer + "/pantherclaw.v1.WorkloadService/IssueToken"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

type world struct {
	d                *dbtest.DB
	pool             *db.Pool
	svc              *app.Service
	inv              *aapp.Inventory
	reg              *keys.Registry
	org              ids.OrgID
	team, env, owner ids.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeWorkloadTokens)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	w := &world{
		d: d, pool: p, reg: reg, svc: app.New(p, reg, issuer, clock.System{}), inv: aapp.NewInventory(p, unlimited{}),
		org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(),
	}
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	return w
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// person returns a caller context for user id with roles at the team.
func (w *world) person(id ids.UUID, kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeTeam, ID: w.team}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

func (w *world) ownerCtx() context.Context {
	return w.person(w.owner, td.KindUser, td.RoleAgentOwner, td.RoleAgentAdmitter)
}

func (w *world) agent(t *testing.T, c adomain.ExecutionContext) ids.UUID {
	t.Helper()
	a, err := w.inv.Create(w.ownerCtx(), adomain.Details{
		Name: "coder", TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner, Context: c,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

type workload struct {
	key ed25519.PrivateKey
	pub ed25519.PublicKey
}

func newWorkload() workload {
	pub, key, _ := ed25519.GenerateKey(nil)
	return workload{key: key, pub: pub}
}

func (wl workload) jwk() []byte {
	b, _ := json.Marshal(jws.PublicJWK(wl.pub, ""))
	return b
}

// checked builds and verifies a key-only proof over body for url.
func (w *world) checked(t *testing.T, wl workload, url string, body []byte) pap.Checked {
	t.Helper()
	n, err := w.svc.Nonce(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: url, Body: body, Nonce: n, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := pap.VerifyRequest(nil, issuer, pap.Request{Method: "POST", URL: url, BodySHA256: sha256.Sum256(body)}, proof, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (w *world) enroll(t *testing.T, wl workload, token string) (app.Enrolled, error) {
	t.Helper()
	return w.svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, wl, enrollURL, []byte(token)), EnrollmentToken: token, PublicJWK: wl.jwk(),
	})
}

func (w *world) enrollmentToken(t *testing.T, agent ids.UUID) string {
	t.Helper()
	et, err := w.svc.CreateEnrollmentToken(w.ownerCtx(), agent, 0)
	if err != nil {
		t.Fatal(err)
	}
	return et.Secret.Reveal()
}

func (w *world) token(wl workload, t *testing.T, id pap.Instance, addr string) (app.Issued, error) {
	t.Helper()
	return w.svc.IssueToken(context.Background(), app.TokenInput{
		Proof: w.checked(t, wl, tokenURL, []byte(id.String())), Identifier: id.String(), ClientAddress: addr,
	})
}

func wantPAP(t *testing.T, what string, err error, code pap.Code) {
	t.Helper()
	if !errors.Is(err, pap.Err(code)) {
		t.Errorf("%s: err = %v, want %s", what, err, code)
	}
}

func wantCode(t *testing.T, what string, err error, code pcerr.Code, reason string) {
	t.Helper()
	if pcerr.CodeOf(err) != code || (reason != "" && pcerr.ReasonOf(err) != reason) {
		t.Errorf("%s: err = %v, want %s %s", what, err, code, reason)
	}
}

// TestHR090_ProofsAreSingleUse: a consumed proof cannot be consumed again,
// and a proof carrying another org's nonce is refused.
func TestHR090_ProofsAreSingleUse(t *testing.T) {
	w := newWorld(t)
	c := w.checked(t, newWorkload(), enrollURL, nil)
	if err := w.svc.Consume(context.Background(), w.org, c); err != nil {
		t.Fatal(err)
	}
	wantPAP(t, "replayed proof", w.svc.Consume(context.Background(), w.org, c), pap.CodeProofReplay)
	other := newWorld(t)
	wantPAP(t, "nonce of another org", other.svc.Consume(context.Background(), other.org, w.checked(t, newWorkload(), enrollURL, nil)), pap.CodeUseNonce)
}

// TestHR091_StaleNoncesAreRefused: a nonce from 7 minutes ago is no longer
// accepted (database clock).
func TestHR091_StaleNoncesAreRefused(t *testing.T) {
	w := newWorld(t)
	stale := "c3RhbGUtc3RhbGUtc3RhbGUtc3RhbGUtc3RhbGU"
	w.exec(t, "INSERT INTO pc.dpop_nonces (org_id, minute, nonce) VALUES ($1, floor(extract(epoch FROM now()) / 60)::bigint - 7, $2)", w.org, stale)
	wl := newWorkload()
	proof, _ := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: enrollURL, Nonce: stale, Now: time.Now()})
	c, err := pap.VerifyRequest(nil, issuer, pap.Request{Method: "POST", URL: enrollURL, BodySHA256: sha256.Sum256(nil)}, proof, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wantPAP(t, "stale nonce", w.svc.Consume(context.Background(), w.org, c), pap.CodeUseNonce)
}

// TestT004_EnrollmentTokensAreSingleUseAndOwnerOnly (PN-002.1).
func TestT004_EnrollmentTokensAreSingleUseAndOwnerOnly(t *testing.T) {
	w := newWorld(t)
	agent := w.agent(t, adomain.ContextCI)
	other := ids.NewV7()
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'mallory')", w.org, other)
	_, err := w.svc.CreateEnrollmentToken(w.person(other, td.KindUser, td.RoleAgentOwner), agent, 0)
	wantCode(t, "non-owner mints a token", err, pcerr.PermissionDenied, "NOT_AGENT_OWNER")
	_, err = w.svc.CreateEnrollmentToken(w.person(ids.NewV7(), td.KindServiceAccount, td.RoleAgentOwner), agent, 0)
	wantCode(t, "service account mints a token", err, pcerr.PermissionDenied, "NOT_AGENT_OWNER")
	tok := w.enrollmentToken(t, agent)
	e, err := w.enroll(t, newWorkload(), tok)
	if err != nil || e.State != "PENDING_ADMISSION" || e.Fingerprint == "" {
		t.Fatalf("enroll: %+v, %v", e, err)
	}
	_, err = w.enroll(t, newWorkload(), tok)
	wantPAP(t, "reused token", err, pap.CodeInvalidToken)
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.enrollment_token_reused'", w.org); n != 1 {
		t.Errorf("reuse audited %d times, want 1", n)
	}
	expired := w.enrollmentToken(t, agent)
	w.d.AdminExec(t, "UPDATE pc.enrollment_tokens SET created_at = now() - interval '20 minutes', expires_at = now() - interval '5 minutes' WHERE org_id = $1 AND state = 'ACTIVE'", w.org)
	_, err = w.enroll(t, newWorkload(), expired)
	wantPAP(t, "expired token", err, pap.CodeInvalidToken)
	wl := newWorkload()
	_, err = w.svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, wl, enrollURL, nil), EnrollmentToken: w.enrollmentToken(t, agent), PublicJWK: newWorkload().jwk(),
	})
	wantPAP(t, "jwk is not the proof key", err, pap.CodeKeyMismatch)
	if n := w.count(t, "SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND subject_type = 'instance' AND state = 'OPEN'", w.org); n != 1 {
		t.Errorf("open ADMISSION entries %d, want 1", n)
	}
}

// TestHR094_AdmissionNeedsTheOwnerAndTheFingerprint, and a stolen
// enrollment token used first is caught by the fingerprint (T-004).
func TestHR094_AdmissionNeedsTheOwnerAndTheFingerprint(t *testing.T) {
	w := newWorld(t)
	agent := w.agent(t, adomain.ContextCI)
	tok := w.enrollmentToken(t, agent)
	thief, mine := newWorkload(), newWorkload()
	stolen, err := w.enroll(t, thief, tok) // the thief races the owner's workload
	if err != nil {
		t.Fatal(err)
	}
	mineFP := jws.Thumbprint(mine.pub)
	_, err = w.svc.Admit(w.ownerCtx(), stolen.Instance.Instance, mineFP)
	wantCode(t, "fingerprint of the owner's own workload", err, pcerr.FailedPrecondition, "FINGERPRINT_MISMATCH")
	_, err = w.svc.Admit(w.person(w.owner, td.KindUser, td.RoleAgentOwner), stolen.Instance.Instance, stolen.Fingerprint)
	wantCode(t, "owner without Agent Admitter", err, pcerr.PermissionDenied, "")
	_, err = w.svc.Admit(w.person(ids.NewV7(), td.KindUser, td.RoleAgentOwner, td.RoleAgentAdmitter), stolen.Instance.Instance, stolen.Fingerprint)
	wantCode(t, "admitter who is not the owner", err, pcerr.PermissionDenied, "NOT_AGENT_OWNER")
	_, err = w.svc.Admit(w.person(w.owner, td.KindServiceAccount, td.RoleAgentOwner, td.RoleAgentAdmitter), stolen.Instance.Instance, stolen.Fingerprint)
	wantCode(t, "service account", err, pcerr.PermissionDenied, "")
	if _, err := w.svc.Reject(w.ownerCtx(), stolen.Instance.Instance, "not my workload's fingerprint"); err != nil {
		t.Fatal(err)
	}
	genuine, err := w.enroll(t, mine, w.enrollmentToken(t, agent))
	if err != nil {
		t.Fatal(err)
	}
	in, err := w.svc.Admit(w.ownerCtx(), genuine.Instance.Instance, mineFP)
	if err != nil || in.State != "ADMITTED" {
		t.Fatalf("admit: %+v, %v", in, err)
	}
	_, err = w.svc.Admit(w.ownerCtx(), genuine.Instance.Instance, mineFP)
	wantCode(t, "admit twice", err, pcerr.FailedPrecondition, "INSTANCE_STATE")
	if n := w.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND id = $2 AND state = 'VERIFIED'", w.org, agent); n != 1 {
		t.Error("the agent did not move to VERIFIED")
	}
	if n := w.count(t, "SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND state = 'OPEN'", w.org); n != 0 {
		t.Errorf("%d entries still open", n)
	}
	_, err = w.enroll(t, mine, w.enrollmentToken(t, agent))
	wantCode(t, "same key enrolled twice", err, pcerr.AlreadyExists, "KEY_ENROLLED")
}

func (w *world) admitted(t *testing.T, c adomain.ExecutionContext) (workload, pap.Instance, ids.UUID) {
	t.Helper()
	agent := w.agent(t, c)
	wl := newWorkload()
	e, err := w.enroll(t, wl, w.enrollmentToken(t, agent))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Admit(w.ownerCtx(), e.Instance.Instance, e.Fingerprint); err != nil {
		t.Fatal(err)
	}
	return wl, e.Instance, agent
}

// TestT032_TokensOnlyForAdmittedInstancesAndTheirKey.
func TestT032_TokensOnlyForAdmittedInstancesAndTheirKey(t *testing.T) {
	w := newWorld(t)
	wl, inst, agent := w.admitted(t, adomain.ContextCI)
	iss, err := w.token(wl, t, inst, "203.0.113.7")
	if err != nil || iss.Level != 1 {
		t.Fatalf("token: %+v, %v", iss, err)
	}
	v, _ := w.svc.TokenVerifier()
	tok, err := pap.VerifyToken(v, issuer, iss.Token, time.Now())
	if err != nil || tok.Instance != inst || tok.JKT != jws.Thumbprint(wl.pub) {
		t.Fatalf("issued token: %+v, %v", tok, err)
	}
	_, err = w.token(newWorkload(), t, inst, "")
	wantPAP(t, "another key", err, pap.CodeKeyMismatch)
	pending := newWorkload()
	pe, _ := w.enroll(t, pending, w.enrollmentToken(t, agent))
	_, err = w.token(pending, t, pe.Instance, "")
	wantPAP(t, "pending instance", err, pap.CodeInstanceNotAdmitted)
	if _, err := w.inv.Suspend(w.ownerCtx(), agent, "investigating"); err != nil {
		t.Fatal(err)
	}
	_, err = w.token(wl, t, inst, "")
	wantPAP(t, "suspended agent", err, pap.CodeInstanceNotAdmitted)
}

// TestHR092_DesktopCapAndNetworkChange: a desktop agent's instance stays L1
// with a current attestation, a CI instance gets L2 that ends with its
// attestation (HR-143), and the same key from a new network is alerted.
func TestHR092_DesktopCapAndNetworkChange(t *testing.T) {
	w := newWorld(t)
	attest := func(inst pap.Instance, until time.Duration) {
		rev := ids.NewV7()
		w.exec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
			binding, state, proposed_by, activated_by, activated_at) VALUES ($1, $2, $3, 1, $4, 'github_actions',
			'https://token.actions.githubusercontent.com', $5, '{RS256}', '{"repository_id":"1"}',
			'ACTIVE', 'test', 'test', now())`, w.org, rev, ids.NewV7(), inst.Agent, "pantherclaw:"+w.org.String())
		w.d.AdminExec(t, `UPDATE pc.agent_instances SET att_level = 2, attested_until = now() + $3::interval, issuer_revision_id = $4,
			binding = '{"repository_id":"1"}' WHERE org_id = $1 AND id = $2`, w.org, inst.Instance, until.String(), rev)
	}
	dwl, desk, _ := w.admitted(t, adomain.ContextDesktop)
	attest(desk, 30*time.Minute)
	if iss, err := w.token(dwl, t, desk, ""); err != nil || iss.Level != 1 {
		t.Fatalf("desktop: %+v, %v", iss, err)
	}
	cwl, ci, _ := w.admitted(t, adomain.ContextCI)
	attest(ci, 3*time.Minute)
	iss, err := w.token(cwl, t, ci, "198.51.100.10")
	if err != nil || iss.Level != 2 || iss.ExpiresAt.After(time.Now().Add(3*time.Minute+5*time.Second)) {
		t.Fatalf("ci: %+v, %v", iss, err)
	}
	if _, err := w.token(cwl, t, ci, "198.51.100.99"); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.instance_network_changed'", w.org); n != 0 {
		t.Fatal("same /24 is not a new network")
	}
	if _, err := w.token(cwl, t, ci, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.instance_network_changed'", w.org); n != 1 {
		t.Fatalf("network change alerts %d, want 1", n)
	}
}

// TestHR147_DeclaredReleaseChangeIsDrift: a new self-reported digest flags
// the instance for review; it stays "declared".
func TestHR147_DeclaredReleaseChangeIsDrift(t *testing.T) {
	w := newWorld(t)
	wl, inst, _ := w.admitted(t, adomain.ContextService)
	for _, d := range []string{"sha256:" + hex64('a'), "sha256:" + hex64('b')} {
		if _, err := w.svc.IssueToken(context.Background(), app.TokenInput{
			Proof: w.checked(t, wl, tokenURL, []byte(d)), Identifier: inst.String(), DeclaredRelease: d,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.svc.GetInstance(w.ownerCtx(), inst.Instance)
	if err != nil || !got.NeedsReview || got.ReleaseState != pap.ReleaseDeclared {
		t.Fatalf("instance %+v, %v", got, err)
	}
}

func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
