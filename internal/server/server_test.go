// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

func noEnv(string) (string, bool) { return "", false }

func TestConfigValidation(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err == nil {
		t.Fatal("defaults without secrets validated")
	}
	c.DB.AppPasswordFile = "pw"
	c.KEKFiles = []string{"kek"}
	if err := c.Validate(); err != nil {
		t.Fatalf("minimal config invalid: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"role":         func(c *Config) { c.Role = "admin" },
		"log level":    func(c *Config) { c.Log.Level = "verbose" },
		"half tls":     func(c *Config) { c.HTTP.TLSCertFile = "cert.pem" },
		"app as owner": func(c *Config) { c.DB.AppUser = "postgres" },
		"app as mig":   func(c *Config) { c.DB.AppUser = "pc_migrator" },
		"no kek":       func(c *Config) { c.KEKFiles = nil },
		"workers":      func(c *Config) { c.WorkerConcurrency = 0 },
		"grant amount": func(c *Config) { c.Authority.GrantMaxPerAction = "-1" },
		"grant ccy":    func(c *Config) { c.Authority.GrantCurrency = "XYZ" },
		"budget name":  func(c *Config) { c.Authority.BudgetName = "" },
		"permit ttl":   func(c *Config) { c.Authority.PermitTTL = 0 },
		"long ttl":     func(c *Config) { c.Authority.PermitTTL = config.Duration(time.Hour) },
		"stale":        func(c *Config) { c.Authority.StaleDispatch = config.Duration(5 * time.Second) },
		"gw no token":  func(c *Config) { c.DevGateway = DevGatewayConfig{Enabled: true, Org: devOrg, ID: "gw"} },
		"gw no org":    func(c *Config) { c.DevGateway = DevGatewayConfig{Enabled: true, TokenFile: "t", ID: "gw"} },
		"gw public": func(c *Config) {
			c.DevGateway = DevGatewayConfig{Enabled: true, TokenFile: "t", Org: devOrg, ID: "gw"}
			c.HTTP.Addr = "0.0.0.0:8080"
		},
		"gw proxy": func(c *Config) {
			c.DevGateway = DevGatewayConfig{Enabled: true, TokenFile: "t", Org: devOrg, ID: "gw"}
			c.HTTP.PlaintextBehindProxy = true
		},
		"public url http":     func(c *Config) { c.Auth.PublicURL = "http://pantherclaw.example.com" },
		"public url path":     func(c *Config) { c.Auth.PublicURL = "https://pc.example.com/api" },
		"public url slash":    func(c *Config) { c.Auth.PublicURL = "https://pc.example.com/" },
		"public url query":    func(c *Config) { c.Auth.PublicURL = "https://pc.example.com?x=1" },
		"public url userinfo": func(c *Config) { c.Auth.PublicURL = "https://u:p@pc.example.com" },
		"public url relative": func(c *Config) { c.Auth.PublicURL = "pc.example.com" },
		"api key env":         func(c *Config) { c.Auth.APIKeyEnv = "prod" },
	} {
		cc := c
		mutate(&cc)
		if err := cc.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, u := range []string{"https://pc.example.com", "https://pc.example.com:8443", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:9000"} {
		cc := c
		cc.Auth.PublicURL = u
		if err := cc.Validate(); err != nil {
			t.Errorf("public url %s refused: %v", u, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:0"} {
		cc := c
		cc.HTTP.Addr = addr
		cc.DevGateway = DevGatewayConfig{Enabled: true, TokenFile: "t", Org: devOrg, ID: "gw"}
		if err := cc.Validate(); err != nil {
			t.Errorf("dev gateway on %s refused: %v", addr, err)
		}
	}
}

const devOrg = "01920000-0000-7000-8000-0000000000a1"

func TestDevGatewayAuthRequiresAStrongToken(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	if auth, err := devGatewayAuth(&c); auth != nil || err != nil {
		t.Fatalf("disabled dev gateway = %v, %v", auth, err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.DevGateway = DevGatewayConfig{Enabled: true, TokenFile: short, Org: devOrg, ID: "gw"}
	if _, err := devGatewayAuth(&c); err == nil {
		t.Fatal("short token accepted")
	}
	good := filepath.Join(dir, "good")
	if err := writeDevToken(good); err != nil {
		t.Fatal(err)
	}
	if err := writeDevToken(good); err == nil {
		t.Fatal("token file overwritten")
	}
	c.DevGateway.TokenFile = good
	if auth, err := devGatewayAuth(&c); auth == nil || err != nil {
		t.Fatalf("good token = %v, %v", auth, err)
	}
}

func TestDevSeedUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"dev"}, {"dev", "drop"}, {"dev", "seed", "extra"}, {"dev", "seed", "--max-count", "-1"}} {
		if code := Run(context.Background(), args, &out, &errb, noEnv); code != 2 {
			t.Errorf("%v: %d, want 2", args, code)
		}
	}
}

func TestRunUsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), nil, &out, &errb, noEnv); code != 2 {
		t.Fatalf("no args: %d", code)
	}
	if code := Run(context.Background(), []string{"bogus"}, &out, &errb, noEnv); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	out.Reset()
	if code := Run(context.Background(), []string{"version"}, &out, &errb, noEnv); code != 0 || !strings.HasPrefix(out.String(), "pantherclaw-server ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestKeysGenKEK(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek")
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"keys", "gen-kek", "--out", p}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("gen-kek: %d %s", code, errb.String())
	}
	if b, err := os.ReadFile(p); err != nil || len(bytes.TrimSpace(b)) != 44 {
		t.Fatalf("KEK file = %q, %v", b, err)
	}
	if code := Run(context.Background(), []string{"keys", "gen-kek", "--out", p}, &out, &errb, noEnv); code == 0 {
		t.Fatal("gen-kek overwrote an existing KEK")
	}
}

func TestServeRefusesInvalidConfigWithoutTouchingTheDatabase(t *testing.T) {
	var errb bytes.Buffer
	env := func(k string) (string, bool) {
		if k == "PC_ROLE" {
			return "superuser", true
		}
		return "", false
	}
	if code := Run(context.Background(), []string{"serve"}, &bytes.Buffer{}, &errb, env); code != 1 || !strings.Contains(errb.String(), "role must be") {
		t.Fatalf("serve with bad role: %d %s", code, errb.String())
	}
}
