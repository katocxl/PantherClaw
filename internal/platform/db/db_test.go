// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func validConfig() Config {
	c := Defaults()
	c.User = RoleApp
	c.Password = pclog.NewSecret([]byte("x"))
	return c
}

func TestConfigValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	cases := map[string]func(*Config){
		"no password":            func(c *Config) { c.Password = pclog.Secret[[]byte]{} },
		"no user":                func(c *Config) { c.User = "" },
		"bad port":               func(c *Config) { c.Port = 0 },
		"disable on remote":      func(c *Config) { c.Host = "db.example.com"; c.SSLMode = "disable" },
		"prefer":                 func(c *Config) { c.SSLMode = "prefer" },
		"require (no verify)":    func(c *Config) { c.SSLMode = "require" },
		"zero statement timeout": func(c *Config) { c.StatementTimeout = 0 },
		"huge lock timeout":      func(c *Config) { c.LockTimeout = time.Hour },
		"no conns":               func(c *Config) { c.MaxConns = 0 },
	}
	for name, mutate := range cases {
		c := validConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		c := validConfig()
		c.Host, c.SSLMode = host, "disable"
		if err := c.Validate(); err != nil {
			t.Errorf("sslmode=disable on %s rejected: %v", host, err)
		}
	}
}

func TestPoolConfigKeepsPasswordOutOfConnString(t *testing.T) {
	c := validConfig()
	c.Password = pclog.NewSecret([]byte("p@ss' word"))
	c.Host = "127.0.0.1"
	c.SSLMode = "disable"
	pc, err := c.poolConfig()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pc.ConnString(), "p@ss") {
		t.Fatalf("password present in connection string %q", pc.ConnString())
	}
	if pc.ConnConfig.Password != "p@ss' word" {
		t.Fatal("password not set on the parsed config")
	}
	rp := pc.ConnConfig.RuntimeParams
	if rp["statement_timeout"] != "5000" || rp["lock_timeout"] != "2000" ||
		rp["idle_in_transaction_session_timeout"] != "10000" || rp["search_path"] != "pc" || rp["row_security"] != "on" {
		t.Fatalf("runtime params = %v", rp)
	}
	if pc.AfterRelease == nil || pc.AfterConnect == nil {
		t.Fatal("pool hooks not installed (HR-052, HR-057)")
	}
}

func TestQuoteKV(t *testing.T) {
	if got := quoteKV(`a'b\c`); got != `'a\'b\\c'` {
		t.Fatalf("quoteKV = %s", got)
	}
}

func TestHR004_ExpectOneRow(t *testing.T) {
	if err := ExpectOneRow(pgconn.NewCommandTag("UPDATE 1"), nil); err != nil {
		t.Fatalf("1 row: %v", err)
	}
	if err := ExpectOneRow(pgconn.NewCommandTag("UPDATE 0"), nil); !errors.Is(err, ErrLostRace) {
		t.Fatalf("0 rows: %v, want ErrLostRace", err)
	}
	if err := ExpectOneRow(pgconn.NewCommandTag("UPDATE 2"), nil); err == nil || errors.Is(err, ErrLostRace) {
		t.Fatalf("2 rows: %v, want a hard failure", err)
	}
	boom := errors.New("boom")
	if err := ExpectOneRow(pgconn.CommandTag{}, boom); !errors.Is(err, boom) {
		t.Fatalf("error passthrough: %v", err)
	}
}

func TestSCRAMVerifierMatchesRFC7677(t *testing.T) {
	// RFC 7677 §3: user "user", password "pencil", 4096 iterations.
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	v, err := scramVerifierWithSalt([]byte("pencil"), salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(v, "SCRAM-SHA-256$"), "$")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "4096:") {
		t.Fatalf("verifier format: %s", v)
	}
	keys := strings.Split(parts[1], ":")
	serverKey, _ := base64.StdEncoding.DecodeString(keys[1])
	authMessage := "n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	m := hmac.New(sha256.New, serverKey)
	m.Write([]byte(authMessage))
	if got := base64.StdEncoding.EncodeToString(m.Sum(nil)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("server signature = %s", got)
	}
}

func TestCheckPassword(t *testing.T) {
	for _, bad := range []string{"short", strings.Repeat("a", 23), strings.Repeat("a", 257), strings.Repeat("a", 23) + " ", strings.Repeat("é", 20)} {
		if checkPassword([]byte(bad)) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := checkPassword([]byte(strings.Repeat("aB3$", 8))); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaFingerprintIsStable(t *testing.T) {
	if a, b := SchemaFingerprint(), SchemaFingerprint(); a != b || len(a) != 16 {
		t.Fatal("fingerprint unstable or wrong length")
	}
}
