// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

type recordKeys struct {
	pantherclawv1connect.UnimplementedPackageServiceHandler
	register *pantherclawv1.RegisterSigningKeyRequest
	revoke   *pantherclawv1.RevokeSigningKeyRequest
	listed   bool
}

func (r *recordKeys) RegisterSigningKey(_ context.Context, req *pantherclawv1.RegisterSigningKeyRequest) (*pantherclawv1.RegisterSigningKeyResponse, error) {
	r.register = req
	return &pantherclawv1.RegisterSigningKeyResponse{Key: &pantherclawv1.SigningKey{Name: req.GetName()}}, nil
}

func (r *recordKeys) RevokeSigningKey(_ context.Context, req *pantherclawv1.RevokeSigningKeyRequest) (*pantherclawv1.RevokeSigningKeyResponse, error) {
	r.revoke = req
	return &pantherclawv1.RevokeSigningKeyResponse{Key: &pantherclawv1.SigningKey{Kid: req.GetKid()}}, nil
}

func (r *recordKeys) ListSigningKeys(context.Context, *pantherclawv1.ListSigningKeysRequest) (*pantherclawv1.ListSigningKeysResponse, error) {
	r.listed = true
	return &pantherclawv1.ListSigningKeysResponse{}, nil
}

// TestHR162_PackageKeyCreateAndSignStayOffline: the private key is made
// and used on this machine; only the public JWK is ever read for the
// server, and signed targets verify against it alone.
func TestHR162_PackageKeyCreateAndSignStayOffline(t *testing.T) {
	dir := t.TempDir()
	env := envOf(map[string]string{})
	pp := filepath.Join(dir, "pp")
	if err := os.WriteFile(pp, []byte("a long enough passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, env, "package-key", "create", "--name", "release", "--out-dir", dir, "--passphrase-file", pp)
	if code != 0 || !strings.Contains(out, trust.OrgKIDPrefix) {
		t.Fatalf("package-key create = %d %q %q", code, out, errs)
	}
	pubJSON, err := os.ReadFile(filepath.Join(dir, "release.pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	kid, pub, err := trust.ParseOrgKey(bytes.TrimSpace(pubJSON))
	if err != nil {
		t.Fatalf("the public key file is not a registrable org key: %v", err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "release.key"))
	if !bytes.Contains(keyPEM, []byte("ENCRYPTED")) || bytes.Contains(pubJSON, []byte(`"d"`)) {
		t.Fatal("the private key must be encrypted and stay out of the public file")
	}
	if code, _, _ := run(t, env, "package-key", "create", "--name", "release", "--out-dir", dir); code == 0 {
		t.Fatal("create overwrote an existing key")
	}

	pkg := []byte(strings.Replace(mockPackage(t), "name: pc.mock-payments", "name: acme.payments", 1))
	pkgFile := filepath.Join(dir, "package.yaml")
	if err := os.WriteFile(pkgFile, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(dir, "targets.jws")
	code, out, errs = run(t, env, "package", "sign", "--key", filepath.Join(dir, "release.key"), "--passphrase-file", pp,
		"--version", "1", "--expires-days", "30", "--out", targets, pkgFile)
	if code != 0 || !strings.Contains(out, "acme.payments@1.0.0") {
		t.Fatalf("package sign = %d %q %q", code, out, errs)
	}
	doc, _ := os.ReadFile(targets)
	v, err := trust.Verify(string(doc), trust.Roots{kid: pub}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Match("acme.payments", "1.0.0", pkg); err != nil {
		t.Fatal(err)
	}

	// PantherClaw's names stay PantherClaw's, and a package root is not an
	// org key.
	if err := os.WriteFile(pkgFile, []byte(mockPackage(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "package", "sign", "--key", filepath.Join(dir, "release.key"), "--passphrase-file", pp,
		"--version", "2", "--expires-days", "30", "--out", filepath.Join(dir, "t2.jws"), pkgFile); code == 0 || !strings.Contains(errs, "pc.mock-payments") {
		t.Fatalf("signing a pc. package = %d %q", code, errs)
	}
	priv, rootKID, _ := rootkey.Generate(rootkey.PurposePackages)
	rootPEM, _ := rootkey.Encode(rootkey.PurposePackages, priv, nil)
	rootFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(rootFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "package", "sign", "--key", rootFile, "--version", "1", "--expires-days", "30",
		"--out", filepath.Join(dir, "t3.jws"), pkgFile); code == 0 || !strings.Contains(errs, "not an org package-signing key") {
		t.Fatalf("signing with %s = %d %q", rootKID, code, errs)
	}
	for _, args := range [][]string{
		{"package", "sign", "--key", "k", "--version", "1", "--expires-days", "400", "--out", "o", "p.yaml"},
		{"package", "sign", "--key", "k", "--version", "0", "--expires-days", "30", "--out", "o", "p.yaml"},
		{"package-key", "create", "--name", "../escape", "--out-dir", dir},
	} {
		if code, _, _ := run(t, env, args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestPackageKeyCommands(t *testing.T) {
	r := &recordKeys{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterPackageServiceHandler(cs, r)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	pubFile := filepath.Join(t.TempDir(), "release.pub.json")
	if err := os.WriteFile(pubFile, []byte(`{"kty":"OKP"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, env, "package-key", "register", "--name", "release", "--public-key-file", pubFile); code != 0 ||
		r.register.GetPublicJwk() != `{"kty":"OKP"}` || r.register.GetName() != "release" {
		t.Fatalf("register = %d %q, sent %v", code, errs, r.register)
	}
	kid := trust.OrgKIDPrefix + strings.Repeat("A", 22)
	if code, _, errs := run(t, env, "package-key", "revoke", kid, "--reason", "compromised"); code != 0 ||
		r.revoke.GetReason() != pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED || r.revoke.GetKid() != kid {
		t.Fatalf("revoke = %d %q, sent %v", code, errs, r.revoke)
	}
	if code, _, errs := run(t, env, "package-key", "revoke", kid, "--reason", "lost"); code == 0 || !strings.Contains(errs, "--reason") {
		t.Fatalf("unknown reason = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "package-key", "list"); code != 0 || !r.listed {
		t.Fatal("list")
	}
}

func mockPackage(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packages", "mock-payments", "package.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
