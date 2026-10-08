// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package billing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var founder = evdomain.Actor{Type: "user", ID: "founder"}

func setup(t *testing.T) (*db.Pool, *jws.Signer, licence.Roots) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jws.NewSigner(licence.RootKID(pub), priv)
	return dbtest.New(t).AppPool(t), s, licence.Roots{licence.RootKID(pub): pub}
}

func doc(t *testing.T, s *jws.Signer, exp time.Time) []byte {
	t.Helper()
	nbf := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d, err := licence.Sign(domain.Claims{
		Version: 1, LicenceID: "lic-" + exp.Format("20060102"), Licensee: "Acme", CustomerID: "cus_1",
		Edition: domain.Team, MaxAgents: 50, MaxOrgs: 3, IssuedAt: nbf, NotBefore: nbf, ExpiresAt: exp,
	}, s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func auditCount(t *testing.T, p *db.Pool, kind string) int {
	t.Helper()
	var n int
	err := p.InTenantTx(context.Background(), ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE kind = $1", kind).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntInstallValidLicence(t *testing.T) {
	p, s, roots := setup(t)
	clk := clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))
	svc := billing.New(p, roots, clk, pclog.Discard())
	ctx := context.Background()
	if e, err := svc.Current(ctx); err != nil || e.Status != domain.StatusCommunity {
		t.Fatalf("before install: %+v, %v", e, err)
	}
	d := doc(t, s, time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC))
	e, err := svc.Install(ctx, d, founder)
	if err != nil || e.Status != domain.StatusValid || e.Limits.MaxAgents != 50 {
		t.Fatalf("install = %+v, %v", e, err)
	}
	// Re-installing the same document (every restart) is a no-op.
	if _, err := svc.Install(ctx, d, founder); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, p, "audit.licence.installed"); n != 1 {
		t.Fatalf("installed audit entries = %d, want 1", n)
	}
	if e, err := svc.Current(ctx); err != nil || e.Edition != domain.Team {
		t.Fatalf("current = %+v, %v", e, err)
	}
}

func TestT034_TamperedLicenceFallsBackToCommunityAndIsAudited(t *testing.T) {
	p, s, roots := setup(t)
	svc := billing.New(p, roots, clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)), pclog.Discard())
	ctx := context.Background()
	good := doc(t, s, time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC))
	if _, err := svc.Install(ctx, good, founder); err != nil {
		t.Fatal(err)
	}
	// Change one base64 character inside the PEM body (the signed bytes).
	body := bytes.IndexByte(good, '\n') + 1
	bad := bytes.Clone(good)
	i := body + bytes.IndexAny(good[body:], "ABCDEFGHIJ")
	bad[i]++
	e, err := svc.Install(ctx, bad, founder)
	if !errors.Is(err, licence.ErrInvalid) || e.Status != domain.StatusInvalid || e.Limits != domain.CommunityLimits {
		t.Fatalf("tampered install = %+v, %v", e, err)
	}
	// The previous valid licence does not linger: Community limits apply now.
	if cur, err := svc.Current(ctx); err != nil || cur.Status != domain.StatusInvalid || cur.Edition != domain.Community {
		t.Fatalf("current after rejection = %+v, %v", cur, err)
	}
	if n := auditCount(t, p, "audit.licence.rejected"); n != 1 {
		t.Fatalf("rejected audit entries = %d, want 1", n)
	}
	// A build with different roots no longer trusts a stored licence.
	if _, err := svc.Install(ctx, good, founder); err != nil {
		t.Fatal(err)
	}
	other := billing.New(p, licence.Roots{}, clock.System{}, pclog.Discard())
	if cur, err := other.Current(ctx); err != nil || cur.Status != domain.StatusInvalid {
		t.Fatalf("current under other roots = %+v, %v", cur, err)
	}
}

func TestT034_ExpiredLicenceGraceThenCommunity(t *testing.T) {
	p, s, roots := setup(t)
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clk := clock.NewFake(exp.Add(-time.Hour))
	svc := billing.New(p, roots, clk, pclog.Discard())
	ctx := context.Background()
	if _, err := svc.Install(ctx, doc(t, s, exp), founder); err != nil {
		t.Fatal(err)
	}
	clk.Set(exp.Add(24 * time.Hour))
	if e, _ := svc.Current(ctx); e.Status != domain.StatusGrace || e.Edition != domain.Team {
		t.Fatalf("one day after expiry: %+v", e)
	}
	clk.Set(exp.Add(domain.GracePeriod + time.Hour))
	if e, _ := svc.Current(ctx); e.Status != domain.StatusExpired || e.Edition != domain.Community || e.Limits != domain.CommunityLimits {
		t.Fatalf("after grace: %+v", e)
	}
}
