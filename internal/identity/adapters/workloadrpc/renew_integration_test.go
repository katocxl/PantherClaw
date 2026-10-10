// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package workloadrpc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// renewOrg is an org with one agent, administered by its owner.
type renewOrg struct {
	org      ids.OrgID
	agent    string
	agents   pantherclawv1connect.AgentServiceClient
	identity pantherclawv1connect.IdentityServiceClient
}

func newRenewOrg(t *testing.T, s *stack) *renewOrg {
	t.Helper()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	team, env := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", org, team)
	s.exec(t, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", org, env, team)
	owner, tok := s.login(t, org, td.RoleAgentOwner, td.RoleAgentAdmitter)
	admin := s.connectClient(bearer{tok})
	o := &renewOrg{
		org: org, agents: pantherclawv1connect.NewAgentServiceClient(admin), identity: pantherclawv1connect.NewIdentityServiceClient(admin),
	}
	a, err := o.agents.CreateAgent(t.Context(), &pantherclawv1.CreateAgentRequest{
		Name: "billing-service", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
		ExecutionContext: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_SERVICE,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.agent = a.GetAgent().GetId()
	return o
}

// admit enrolls a new key for the agent and admits it; it returns a
// renewer for that instance on clk that delivers into tokenFile.
func (o *renewOrg) admit(t *testing.T, s *stack, clk clock.Clock, tokenFile string) (*workloadclient.Renewer, string) {
	t.Helper()
	ctx := t.Context()
	et, err := o.identity.CreateEnrollmentToken(ctx, &pantherclawv1.CreateEnrollmentTokenRequest{AgentId: o.agent})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	wc := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: key, Now: clk.Now}))
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	e, err := wc.Enroll(ctx, &pantherclawv1.EnrollRequest{EnrollmentToken: et.GetToken(), PublicJwk: string(jwk)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{Id: e.GetInstanceId(), Fingerprint: e.GetFingerprint()}); err != nil {
		t.Fatal(err)
	}
	return &workloadclient.Renewer{
		Issue: func(ctx context.Context) (workloadclient.Issued, error) {
			res, err := wc.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: e.GetIdentifier()})
			if err != nil {
				return workloadclient.Issued{}, err
			}
			return workloadclient.Issued{Token: res.GetWorkloadToken(), ExpiresAt: res.GetExpireTime().AsTime(), Level: int(res.GetAttestationLevel())}, nil
		},
		Deliver: func(iss workloadclient.Issued) error { return workloadclient.WriteTokenFile(tokenFile, iss.Token) },
		Report:  func(r string) { t.Errorf("renewal failed: %s", r) },
		Clock:   clk,
		Rand:    func() float64 { return 0.5 },
	}, e.GetInstanceId()
}

// TestIntRenewerKeepsAValidTokenAcrossExpiries: a long-running renewer,
// on a clock shared with the server, keeps a token in its file that the
// server accepts at every 30-second step across five token lifetimes,
// with the kill switch engaged (it stops actions, not identity; decision
// 3). Revoking the instance then ends renewal with
// instance_not_admitted, and so does suspending the agent.
func TestIntRenewerKeepsAValidTokenAcrossExpiries(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := newStackAt(t, clk)
	o := newRenewOrg(t, s)
	tokenFile := filepath.Join(t.TempDir(), "token")
	r, instance := o.admit(t, s, clk, tokenFile)
	other := filepath.Join(t.TempDir(), "token")
	r2, _ := o.admit(t, s, clk, other) // before the clock moves: enrollment tokens expire
	verifier, err := s.svc.TokenVerifier()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() error {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return err
		}
		_, err = pap.VerifyToken(verifier, s.url, strings.TrimSpace(string(b)), clk.Now())
		return err
	}

	// The kill switch stops actions, not identity (decision 3).
	s.exec(t, o.org, `INSERT INTO pc.org_containment (org_id, kill_switch, engaged_by, engaged_at, engage_reason)
		VALUES ($1, true, 'test', now(), 'drill')
		ON CONFLICT (org_id) DO UPDATE SET kill_switch = true, engaged_by = 'test', engaged_at = now(), engage_reason = 'drill'`, o.org)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	start, seen := clk.Now(), map[string]bool{}
	const span = 5 * workloadclient.MaxLifetime
	r.Sleep = func(ctx context.Context, d time.Duration) error {
		b, _ := os.ReadFile(tokenFile)
		seen[string(b)] = true
		for end := clk.Now().Add(d); clk.Now().Before(end); {
			clk.Advance(min(30*time.Second, end.Sub(clk.Now())))
			if err := valid(); err != nil {
				t.Fatalf("at +%v the token file holds no valid token: %v", clk.Now().Sub(start), err)
			}
		}
		if clk.Now().Sub(start) >= span {
			stop()
		}
		return ctx.Err()
	}
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	// One renewal every 4m45s (half the lifetime, less the jitter) over 50
	// minutes, each a new token.
	if n := len(seen); n < 10 || n > 12 {
		t.Fatalf("%d distinct tokens over %v", n, span)
	}

	ctx = t.Context()
	if _, err := o.identity.RevokeInstance(ctx, &pantherclawv1.RevokeInstanceRequest{Id: instance, Reason: "key copied"}); err != nil {
		t.Fatal(err)
	}
	refused := func(r *workloadclient.Renewer) {
		t.Helper()
		r.Sleep = func(context.Context, time.Duration) error { return nil }
		var refusal *workloadclient.RefusalError
		if err := r.Run(ctx); !errors.As(err, &refusal) || refusal.Code != pap.CodeInstanceNotAdmitted {
			t.Fatalf("Run after the refusal = %v", err)
		}
	}
	refused(r)

	if err := r2.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := o.agents.SuspendAgent(ctx, &pantherclawv1.SuspendAgentRequest{Id: o.agent, Reason: "investigating"}); err != nil {
		t.Fatal(err)
	}
	refused(r2)
	if _, err := os.Stat(other); errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the renewer itself removed the file; that is the command's job")
	}
}
