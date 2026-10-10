// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// devKeyConfig is a development configuration that trusts the
// development package key in dir.
func devKeyConfig(dir string) Config {
	c := DefaultConfig()
	c.DB.AppPasswordFile = "pw"
	c.KEKFiles = []string{"kek"}
	c.Auth.APIKeyEnv = "dev"
	c.GatewayAPI = GatewayAPIConfig{Addr: "127.0.0.1:8443", Hostnames: []string{"127.0.0.1", "localhost"}, URL: "https://127.0.0.1:8443"}
	c.Dev.PackageKeyFile = filepath.Join(dir, "package-dev.pub.json")
	return c
}

// TestHR163_DevPackageKeyOnlyOnLoopback: a configuration that names the
// development package key is refused unless every listener, the gateway
// names and the public URL are on loopback, no proxy is declared and API
// keys are not live; only a configuration file can name it.
func TestHR163_DevPackageKeyOnlyOnLoopback(t *testing.T) {
	ok := devKeyConfig(t.TempDir())
	if err := ok.Validate(); err != nil {
		t.Fatalf("development configuration refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"all interfaces":   func(c *Config) { c.HTTP.Addr = "0.0.0.0:8080" },
		"no host":          func(c *Config) { c.HTTP.Addr = ":8080" },
		"private address":  func(c *Config) { c.HTTP.Addr = "10.0.0.5:8080" },
		"behind a proxy":   func(c *Config) { c.HTTP.PlaintextBehindProxy = true },
		"trusted proxies":  func(c *Config) { c.HTTP.TrustedProxies = []string{"127.0.0.1"} },
		"public url":       func(c *Config) { c.Auth.PublicURL = "https://pantherclaw.example.com" },
		"gateway listener": func(c *Config) { c.GatewayAPI.Addr = "0.0.0.0:8443" },
		"gateway hostname": func(c *Config) { c.GatewayAPI.Hostnames = append(c.GatewayAPI.Hostnames, "gw.example.com") },
		"gateway url": func(c *Config) {
			c.GatewayAPI.Hostnames, c.GatewayAPI.URL = []string{"gw.example.com"}, "https://gw.example.com:8443"
		},
		"live api keys":        func(c *Config) { c.Auth.APIKeyEnv = "live" },
		"not a public jwks":    func(c *Config) { c.Dev.PackageKeyFile = strings.TrimSuffix(c.Dev.PackageKeyFile, ".pub.json") + ".key" },
		"defaults (live keys)": func(c *Config) { c.Auth.APIKeyEnv = DefaultConfig().Auth.APIKeyEnv },
	} {
		c := devKeyConfig(t.TempDir())
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: a configuration naming the development key validated", name)
		}
		c.Dev = DevConfig{}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: refused even without the development key: %v", name, err)
		}
	}
	// No gateway listener at all is local too.
	c := devKeyConfig(t.TempDir())
	c.GatewayAPI = GatewayAPIConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("without a gateway listener: %v", err)
	}

	// No environment variable names the key.
	loaded := DefaultConfig()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(`{"database": {"app_password_file": "pw"}, "kek_files": ["kek"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	everyEnv := func(name string) (string, bool) {
		if strings.HasPrefix(name, "PC_DEV") {
			return "deploy/dev/secrets/package-dev.pub.json", true
		}
		return "", false
	}
	if err := config.Load(&loaded, path, everyEnv); err != nil || loaded.Dev.PackageKeyFile != "" {
		t.Fatalf("the environment named the development key: %q, %v", loaded.Dev.PackageKeyFile, err)
	}

	// The development example configuration names it, and is local.
	example := DefaultConfig()
	if err := config.Load(&example, filepath.Join("..", "..", "deploy", "dev", "server.example.json"), noEnv); err != nil ||
		example.Dev.PackageKeyFile != "deploy/dev/secrets/package-dev.pub.json" {
		t.Fatalf("deploy/dev/server.example.json: %q, %v", example.Dev.PackageKeyFile, err)
	}
}

// TestHR163_ProductionConfigsDoNotTrustTheDevKey: without the setting the
// API trusts exactly the embedded package roots, even when the development
// key files exist; with it, a configuration that is not local is refused
// here too, and a missing key file trusts nothing extra.
func TestHR163_ProductionConfigsDoNotTrustTheDevKey(t *testing.T) {
	ctx := context.Background()
	log := pclog.New(io.Discard, pclog.Options{})
	dir := t.TempDir()
	dev := devKeyConfig(dir)
	signer, err := devPackageSigner(&dev, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := trust.EmbeddedRoots()
	if err != nil {
		t.Fatal(err)
	}

	prod := devKeyConfig(dir)
	prod.Dev = DevConfig{}
	prod.HTTP.Addr, prod.Auth.PublicURL, prod.Auth.APIKeyEnv = "0.0.0.0:8080", "https://pantherclaw.example.com", "live"
	roots, err := packageRoots(ctx, &prod, log)
	if err != nil || len(roots) != len(embedded) || roots[signer.KeyID()] != nil {
		t.Fatalf("production roots = %v, %v", roots, err)
	}
	for kid := range roots {
		if trust.IsDevKID(kid) {
			t.Fatalf("production trusts %s", kid)
		}
	}
	local := devKeyConfig(dir)
	local.Dev = DevConfig{}
	if roots, err := packageRoots(ctx, &local, log); err != nil || len(roots) != len(embedded) {
		t.Fatalf("a local server without the setting trusts %v, %v", roots, err)
	}

	var logs bytes.Buffer
	roots, err = packageRoots(ctx, &dev, pclog.New(&logs, pclog.Options{}))
	if err != nil || !roots[signer.KeyID()].Equal(signer.Public()) || len(roots) != len(embedded)+1 ||
		!strings.Contains(logs.String(), "packages.dev_key_trusted") {
		t.Fatalf("development roots = %v, %v\n%s", roots, err, logs.String())
	}

	exposed := devKeyConfig(dir)
	exposed.HTTP.Addr = "0.0.0.0:8080"
	if _, err := packageRoots(ctx, &exposed, log); err == nil || !strings.Contains(err.Error(), "HR-163") {
		t.Fatalf("an exposed server loaded the development key: %v", err)
	}
	missing := devKeyConfig(t.TempDir())
	if roots, err := packageRoots(ctx, &missing, log); err != nil || len(roots) != len(embedded) {
		t.Fatalf("missing key file: %v, %v", roots, err)
	}
}

// TestHR163_DevSeedKeepsOneDevelopmentKey: dev seed creates the pair once
// and reuses it; it refuses halves that do not belong together and a key
// of another purpose. Without the setting it signs with a throwaway key.
func TestHR163_DevSeedKeepsOneDevelopmentKey(t *testing.T) {
	dir := t.TempDir()
	cfg := devKeyConfig(dir)
	var out bytes.Buffer
	first, err := devPackageSigner(&cfg, &out)
	if err != nil || !trust.IsDevKID(first.KeyID()) || !strings.Contains(out.String(), "created development package key") {
		t.Fatalf("first run: %v, %v, %q", first, err, out.String())
	}
	out.Reset()
	again, err := devPackageSigner(&cfg, &out)
	if err != nil || again.KeyID() != first.KeyID() || out.Len() != 0 {
		t.Fatalf("second run: %v, %v, %q", again, err, out.String())
	}

	priv := filepath.Join(dir, "package-dev.key")
	pub := cfg.Dev.PackageKeyFile
	pubJSON, _ := os.ReadFile(pub)
	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}
	if s, err := devPackageSigner(&cfg, io.Discard); err != nil || s.KeyID() != first.KeyID() {
		t.Fatalf("public half rewritten: %v, %v", s, err)
	}
	if b, _ := os.ReadFile(pub); !bytes.Equal(b, pubJSON) {
		t.Fatalf("rewritten public half %s, want %s", b, pubJSON)
	}

	other := devKeyConfig(t.TempDir())
	if _, err := devPackageSigner(&other, io.Discard); err != nil {
		t.Fatal(err)
	}
	foreign, _ := os.ReadFile(other.Dev.PackageKeyFile)
	if err := os.WriteFile(pub, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := devPackageSigner(&cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "does not hold the public half") {
		t.Fatalf("mismatched pair: %v", err)
	}
	if err := os.Remove(priv); err != nil {
		t.Fatal(err)
	}
	if _, err := devPackageSigner(&cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "without its private key") {
		t.Fatalf("public half alone: %v", err)
	}

	rootDir := t.TempDir()
	rootCfg := devKeyConfig(rootDir)
	k, _, _ := rootkey.Generate(rootkey.PurposePackages)
	pem, _ := rootkey.Encode(rootkey.PurposePackages, k, nil)
	if err := os.WriteFile(filepath.Join(rootDir, "package-dev.key"), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := devPackageSigner(&rootCfg, io.Discard); err == nil || !strings.Contains(err.Error(), "not a development package key") {
		t.Fatalf("a package root used as the development key: %v", err)
	}

	throwaway := devKeyConfig(t.TempDir())
	throwaway.Dev = DevConfig{}
	if s, err := devPackageSigner(&throwaway, io.Discard); err != nil || !strings.HasPrefix(s.KeyID(), trust.KIDPrefix) {
		t.Fatalf("without the setting: %v, %v", s, err)
	}
}
