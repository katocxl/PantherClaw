// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/admincli"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
)

// TestHR163_DevSeedThenImportThroughPackageService: with the development
// configuration, dev seed creates the development package key once, reuses
// it, and signs the reference package with it; a package a developer signs
// with that key (pclaw-admin packages sign) then imports through
// PackageService on the local server, while the same request to a server
// without dev.package_key_file is untrusted.
func TestHR163_DevSeedThenImportThroughPackageService(t *testing.T) {
	d := dbtest.New(t)
	keyDir := t.TempDir()
	pubFile := filepath.Join(keyDir, "package-dev.pub.json")
	local := func(c map[string]any) {
		c["auth"] = map[string]any{"public_url": "http://127.0.0.1:8080", "api_key_env": "dev"}
	}
	devCfg := testConfig(t, d, RoleAPI, local, func(c map[string]any) {
		c["dev"] = map[string]any{"package_key_file": pubFile}
	})
	plainCfg := withoutDevKey(t, devCfg)

	org := devSeedOnly(t, devCfg, true)
	devSeedOnly(t, devCfg, false)
	var kid string
	err := d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		var body []byte
		if err := tx.QueryRow(ctx, "SELECT body FROM pc.ledger_entries WHERE kind = 'audit.package.imported'").Scan(&body); err != nil {
			return err
		}
		var ev struct {
			Details map[string]string `json:"details"`
		}
		if err := json.Unmarshal(body, &ev); err != nil {
			return err
		}
		kid = ev.Details["signing_key"]
		return nil
	})
	if err != nil || !trust.IsDevKID(kid) {
		t.Fatalf("dev seed imported the reference package with %q, %v", kid, err)
	}

	// The developer signs pc.shell with the development key, from targets
	// version 2 (dev seed used 1 in this org).
	shell := filepath.Join("..", "..", "packages", "pc-shell", "package.yaml")
	raw, err := os.ReadFile(shell)
	if err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(t.TempDir(), "targets.jws")
	var out, errb bytes.Buffer
	if code := admincli.Run([]string{
		"packages", "sign", "--key", filepath.Join(keyDir, "package-dev.key"),
		"--version", "2", "--expires-days", "30", "--out", targets, shell,
	}, &out, &errb, time.Now); code != 0 || !strings.Contains(out.String(), kid) {
		t.Fatalf("pclaw-admin packages sign: %d %s%s", code, out.String(), errb.String())
	}
	doc, err := os.ReadFile(targets)
	if err != nil {
		t.Fatal(err)
	}
	req := &pantherclawv1.ImportPackageRequest{Name: pcshell.Name, Version: pcshell.Version, Targets: string(doc), Package: raw}
	key := packageImporterKey(t, d, org)

	_, err = packageClient(serve(t, plainCfg), key).ImportPackage(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a server without the development key imported it: %v", err)
	}
	res, err := packageClient(serve(t, devCfg), key).ImportPackage(context.Background(), req)
	if err != nil || res.GetPackage().GetState() != pantherclawv1.PackageState_PACKAGE_STATE_REVIEWED || res.GetAlreadyImported() {
		t.Fatalf("ImportPackage on the development server = %v, %v", res, err)
	}
}

// withoutDevKey writes a copy of the configuration at path, with the same
// database and key-encryption key, that does not name the development key.
func withoutDevKey(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	delete(c, "dev")
	if b, err = json.Marshal(c); err != nil {
		t.Fatal(err)
	}
	return secretFile(t, filepath.Dir(path), "server-plain.json", b)
}

// devSeedOnly runs a bare `dev seed` and returns the new org; created says
// whether this run must create the development package key.
func devSeedOnly(t *testing.T, cfgPath string, created bool) ids.OrgID {
	t.Helper()
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"dev", "seed", "--config", cfgPath, "--org-name", "acme"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev seed: %d %s", code, errb.String())
	}
	if strings.Contains(out.String(), "created development package key") != created {
		t.Fatalf("dev seed output %q (want created=%v)", out.String(), created)
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	return ids.MustParse[ids.Org](m[1])
}

// packageImporterKey creates an Org Admin service account in org with an
// API key limited to package.import, and returns the key.
func packageImporterKey(t *testing.T, d *dbtest.DB, org ids.OrgID) string {
	t.Helper()
	key, err := credential.New(credential.APIKey, credential.EnvDev, org)
	if err != nil {
		t.Fatal(err)
	}
	sa := ids.NewV7()
	err = d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'packager', 'test')", org, sa); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(tdomain.RoleOrgAdmin), sa); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
			VALUES ($1, $2, $3, 'key', $4, $5, $6, 'test', now() + interval '1 day')`,
			org, ids.NewV7(), sa, key.Hash(), key.Hint(), []string{string(tdomain.PermPackageImport)})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return key.Reveal()
}

func packageClient(base, key string) pantherclawv1connect.PackageServiceClient {
	return pantherclawv1connect.NewPackageServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 10 * time.Second, Transport: bearer{key},
	}, base)))
}
