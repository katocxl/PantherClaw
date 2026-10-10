// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR180_TheGatewayCAIsReplacedAndTheOldOneUntrusted: keys
// rotate-gateway-ca changes nothing without --confirm; with it, the CA has
// a new key and pin, every earlier key is revoked, and a certificate the
// old CA issued is no longer trusted (founder decision 2026-10-10: gateways
// enroll again with the new pin).
func TestHR180_TheGatewayCAIsReplacedAndTheOldOneUntrusted(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		KEKFiles []string `json:"kek_files"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		t.Fatal(err)
	}
	pool := d.AppPool(t)
	load := func() (*ca.Authority, int) {
		t.Helper()
		reg := keys.NewRegistry()
		if err := keystore.LoadSigningKeys(context.Background(), pool, kp, reg); err != nil {
			t.Fatal(err)
		}
		a, err := ca.New(reg)
		if err != nil {
			t.Fatal(err)
		}
		return a, len(reg.Keys(keys.PurposeGatewayCA))
	}
	before, _ := load()
	pin := ca.Fingerprint(before.Certificate())
	pub, _, _ := ed25519.GenerateKey(nil)
	issued, err := before.IssueClient(pub, ca.Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7(), Cert: ids.NewV7()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(a *ca.Authority) error {
		_, err := cert.Verify(x509.VerifyOptions{Roots: a.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	if err := verify(before); err != nil {
		t.Fatalf("the current CA does not trust its own certificate: %v", err)
	}

	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(context.Background(), append([]string{"keys", "rotate-gateway-ca", "--config", cfgPath}, args...), &out, &errb, noEnv)
		return code, out.String(), errb.String()
	}
	if code, _, errs := run(); code == 0 || !strings.Contains(errs, "--confirm") {
		t.Fatalf("without --confirm = %d %s", code, errs)
	}
	if a, _ := load(); ca.Fingerprint(a.Certificate()) != pin {
		t.Fatal("the CA changed without --confirm")
	}
	code, out, errs := run("--confirm")
	if code != 0 || !strings.Contains(out, "replaced the gateway CA") || !strings.Contains(out, "(was "+pin+")") ||
		!strings.Contains(out, "revoked 1 earlier key") {
		t.Fatalf("rotate-gateway-ca = %d %q %q", code, out, errs)
	}
	after, n := load()
	if newPin := ca.Fingerprint(after.Certificate()); newPin == pin || !strings.Contains(out, newPin) || n != 1 {
		t.Fatalf("after: pin %s (was %s), %d CA keys loaded", newPin, pin, n)
	}
	if err := verify(after); err == nil {
		t.Fatal("a certificate of the replaced CA is still trusted")
	}
}
