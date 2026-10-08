// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
)

func TestIntBootstrapCreatesOrgWithOneTimeAdminToken(t *testing.T) {
	f := newFixture(t)
	f.ents.edition = billing.Community
	b := app.NewBootstrap(f.pool, f.ents)
	ctx := context.Background()

	org, tok, err := b.CreateOrg(ctx, "  Acme  ", "Admin@Acme.TEST")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := credential.Parse(credential.Invitation, tok.Reveal())
	if err != nil || parsed.Org() != org {
		t.Fatalf("token %v does not belong to %s: %v", tok, org, err)
	}
	var name, kind, email, state string
	var roles []string
	var hours float64
	var containment int
	err = f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, "SELECT name FROM pc.orgs").Scan(&name); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc.org_containment").Scan(&containment); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT kind, email, roles, state, extract(epoch FROM expires_at - created_at) / 3600
			FROM pc.invitations WHERE token_hash = $1`, tok.Hash()).Scan(&kind, &email, &roles, &state, &hours)
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "Acme" || containment != 1 || kind != "BOOTSTRAP" || email != "admin@acme.test" || state != "PENDING" ||
		len(roles) != 1 || roles[0] != "org_admin" || hours < 23.9 || hours > 24.1 {
		t.Fatalf("org %q containment %d invitation %s %s %v %s %.1fh", name, containment, kind, email, roles, state, hours)
	}
	if f.auditCount(t, org, "tenancy.org_created") != 1 || f.auditCount(t, org, "access.bootstrap_invitation_created") != 1 {
		t.Fatal("bootstrap not audited")
	}

	// Community allows one organization (the platform org does not count).
	_, _, err = b.CreateOrg(ctx, "Second", "")
	if !errors.Is(err, app.ErrOrgLimit) {
		t.Fatalf("second org on Community: %v", err)
	}
	f.ents.edition = billing.Enterprise // Unlimited is not set by the fake: still 1
	if _, _, err := b.CreateOrg(ctx, "", ""); pcerr.CodeOf(err) != pcerr.InvalidArgument {
		t.Fatalf("empty name: %v", err)
	}

	// Recovery: a new token revokes the unused one.
	tok2, err := b.AdminInvitation(ctx, org, "")
	if err != nil {
		t.Fatal(err)
	}
	var pending, revoked int
	err = f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'PENDING' AND token_hash = $1),
			count(*) FILTER (WHERE state = 'REVOKED' AND token_hash = $2) FROM pc.invitations`, tok2.Hash(), tok.Hash()).Scan(&pending, &revoked)
	})
	if err != nil || pending != 1 || revoked != 1 {
		t.Fatalf("pending %d revoked %d (%v)", pending, revoked, err)
	}
	if _, err := b.AdminInvitation(ctx, ids.New[ids.Org](), ""); pcerr.CodeOf(err) != pcerr.NotFound {
		t.Fatalf("unknown org: %v", err)
	}
}
