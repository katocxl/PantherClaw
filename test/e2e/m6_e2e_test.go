// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// The M6 refund scenarios that need custody, egress guards and the kill
// switch (G0 M6, the refund table). The test acts for the people involved
// through the use cases the API and the pages call.

// S11, custody: the target accepts only requests carrying the credential
// PantherClaw holds (HR-061). The agent never has it, so a call straight to
// the target is refused; the same refund through the gateway, which opens
// the sealed credential and places it, is accepted.
func TestS11_TheTargetRefusesCallsWithoutTheCustodyCredential(t *testing.T) {
	s := start(t, options{budget: "1000.00", access: capp.AccessHeld, token: "e2e-held-credential"})
	if code, reason := s.direct(t); code != http.StatusUnauthorized || reason != "credential_required" {
		t.Fatalf("direct call: %d %s, want 401 credential_required", code, reason)
	}
	if code, r := s.refund(t, ids.NewV7(), "30.00"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("through the gateway: %d %+v", code, r)
	}
	if st := s.sim.Stats(); st.Refunds != 1 || st.Refused != 1 {
		t.Fatalf("target stats %+v, want one refund and one refusal", st)
	}
}

// S11, target enforced: the target checks that each refund carries an
// action token the Authority signed for exactly this call (PAP-1 §10). A
// call straight to the target has none; the gateway forwards the token
// BeginDispatch returned.
func TestS11_ATargetEnforcedTargetRefusesCallsWithoutAnActionToken(t *testing.T) {
	s := start(t, options{budget: "1000.00", access: capp.AccessTargetEnforced, actionTokens: true})
	if code, reason := s.direct(t); code != http.StatusForbidden || reason != "action_token_required" {
		t.Fatalf("direct call: %d %s, want 403 action_token_required", code, reason)
	}
	if code, r := s.refund(t, ids.NewV7(), "30.00"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("through the gateway: %d %+v", code, r)
	}
	if st := s.sim.Stats(); st.Refunds != 1 || st.Refused != 1 {
		t.Fatalf("target stats %+v, want one refund and one refusal", st)
	}
}

// S12: requests the gateway must never make (HR-070, HR-077).
//   - A connection cannot name a metadata service or PantherClaw itself.
//   - A connection to an address the operator did not allow passes
//     registration, but the gateway's dial-time guard refuses it: nothing is
//     sent and nothing stays reserved.
//   - A redirect from the target is never followed: the outcome is UNKNOWN
//     and the reservation stays held, like any doubt after sending.
func TestS12_EgressGuardsBlockSSRFAndRedirects(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(other.Close)
	s := start(t, options{budget: "1000.00", faults: payments.Faults{RedirectTo: other.URL + "/v1/refunds"}})
	ctx := context.Background()
	gw := s.gatewayID(t)
	conns := capp.New(s.pool, nil, s.apiURL, "")
	connection := func(name, base string) (capp.Connection, error) {
		return conns.Seed(ctx, s.org, "e2e", capp.CreateInput{
			Name: name, Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: base, Gateway: gw,
			DestinationClass: capp.ClassInternal, AccessMode: capp.AccessNone, DefaultMode: capp.ModeEnforce,
		})
	}

	for name, base := range map[string]string{
		"metadata-address": "http://169.254.169.254/latest", "metadata-name": "https://metadata.google.internal", "itself": s.apiURL,
	} {
		if _, err := connection(name, base); !errors.Is(err, capp.ErrBaseURL) && !errors.Is(err, capp.ErrOwnHost) {
			t.Errorf("connection to %s: %v, want refused", base, err)
		}
	}

	// 127.0.0.2 is loopback, so registration takes it, but the operator
	// allowed only 127.0.0.1/32.
	if _, err := connection("unlisted", "http://127.0.0.2:9"); err != nil {
		t.Fatal(err)
	}
	s.waitConfig(t, s.configVersion(t, gw))
	code, r, err := s.tryRefundVia("unlisted", ids.NewV7(), "30.00")
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusBadGateway || r.ErrorClass != "enforcement_failed" || r.Error != "egress_denied" || r.Outcome != "FAILED" {
		t.Fatalf("unlisted address: %d %+v", code, r)
	}
	// The permit was used and its execution recorded as failed: the
	// reservation is released and nothing was spent.
	if reserved, spent, permit := s.budget(t, r.TransactionID); reserved != "0" || spent != "0" || permit != "DISPATCHED" {
		t.Fatalf("unlisted address: reserved=%s spent=%s permit=%s", reserved, spent, permit)
	}

	code, r = s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("redirect: %d %+v", code, r)
	}
	if reserved, _, permit := s.budget(t, r.TransactionID); reserved != "30" || permit != "UNKNOWN" {
		t.Fatalf("redirect: reserved=%s permit=%s, want held", reserved, permit)
	}
	if st := s.sim.Stats(); st.Redirects != 1 || st.Refunds != 0 || elsewhere.Load() != 0 {
		t.Fatalf("redirect followed: target %+v, redirect target calls %d", st, elsewhere.Load())
	}
}

// S13: the kill switch engaged mid-run. One emergency responder with a
// fresh step-up engages it (HR-113). From then on the Authority denies, and
// within a second the gateway refuses every dispatch itself, without asking
// (HR-002, HR-010). Nothing more reaches the target.
func TestS13_TheKillSwitchStopsDispatchWithinASecond(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	if code, r := s.refund(t, ids.NewV7(), "30.00"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("before: %d %+v", code, r)
	}
	alice := s.person(t, "alice", td.RoleEmergency)
	ks := rapp.New(s.pool, nil, s.apiURL)
	if _, err := ks.Engage(alice.ctx, rapp.StepUp{Credential: alice.key, At: time.Now()}, "e2e incident"); err != nil {
		t.Fatal(err)
	}
	engaged := time.Now()
	for {
		code, r := s.refund(t, ids.NewV7(), "30.00")
		if code == http.StatusOK {
			t.Fatalf("dispatched after the kill switch: %+v", r)
		}
		if r.Error == "kill_switch" {
			if code != http.StatusForbidden || r.ErrorClass != "enforcement_failed" {
				t.Fatalf("gateway refusal: %d %+v", code, r)
			}
			break
		}
		if time.Since(engaged) > time.Second {
			t.Fatalf("the gateway still asks the Authority %s after the kill switch: %d %+v", time.Since(engaged), code, r)
		}
	}
	if st := s.sim.Stats(); st.Refunds != 1 || s.simCalls.Load() != 1 {
		t.Fatalf("target %+v, calls %d, want only the refund before", st, s.simCalls.Load())
	}
}

// direct sends a refund straight to the target, as an agent holding no
// credential and no action token would, and returns the target's status
// and error.
func (s *stack) direct(t *testing.T) (int, string) {
	t.Helper()
	body := `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.simURL+"/v1/refunds", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "direct-"+ids.NewV7().String())
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out.Error
}

// person is a user of the seeded org with one security key, acting with
// one role.
type person struct {
	ctx context.Context
	key ids.UUID
}

func (s *stack) person(t *testing.T, name string, role td.RoleName) person {
	t.Helper()
	id, key := ids.NewV7(), ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, id, name)
	s.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		s.org, key, id, []byte("cred-"+name+"-0123456789"), []byte("public-key-of-"+name+"-0123456789abcdefghijklmnop"))
	return person{key: key, ctx: tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})}
}

// sealCredential seals secret for the payments connection, as a gateway
// admin does with pclaw seal, and returns the gateway configuration version
// that carries it.
func (s *stack) sealCredential(t *testing.T, secret string) int64 {
	t.Helper()
	admin := s.person(t, "gateway-admin", td.RoleGatewayAdmin)
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin.ctx, s.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	brokerKey, err := ids.ParseUUID(k.Binding.BrokerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin.ctx, credapp.PutInput{
		Connection: s.conn, BrokerKey: brokerKey, Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// waitConfig waits until the gateway serves configuration version (or a
// later one).
func (s *stack) waitConfig(t *testing.T, version int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for s.gw.ConfigVersion() < version {
		if time.Now().After(deadline) {
			t.Fatalf("the gateway serves configuration %d, want %d", s.gw.ConfigVersion(), version)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *stack) configVersion(t *testing.T, gw ids.UUID) int64 {
	t.Helper()
	var v int64
	s.query(t, "SELECT config_version FROM pc.gateways WHERE id = $1", []any{gw}, &v)
	return v
}

func (s *stack) gatewayID(t *testing.T) ids.UUID {
	t.Helper()
	var id ids.UUID
	s.query(t, "SELECT gateway_id FROM pc.connections WHERE id = $1", []any{s.conn}, &id)
	return id
}

func mustUUID(t *testing.T, s string) ids.UUID {
	t.Helper()
	id, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *stack) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (s *stack) query(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(dest...)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
