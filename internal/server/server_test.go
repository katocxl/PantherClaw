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
	} {
		cc := c
		mutate(&cc)
		if err := cc.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
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
