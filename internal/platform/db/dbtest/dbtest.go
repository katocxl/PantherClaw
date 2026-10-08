// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package dbtest provides disposable PostgreSQL databases for integration
// tests (build tag `integration`, BUILD_GUIDE §3.5).
//
// It needs a superuser URL for a throwaway cluster in PC_TEST_PG_ADMIN_URL
// (`task up PROFILE=test` starts one on 127.0.0.1:5433; CI uses a service
// container). Roles are bootstrapped once per cluster with passwords derived
// from the admin password, a migrated template database is built once per
// schema fingerprint, and every test gets its own clone. Tests connect as
// pc_app, never as a superuser, because superusers bypass RLS.
package dbtest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Environment variables.
const (
	AdminURLEnv = "PC_TEST_PG_ADMIN_URL"
	// RequireEnv set to "1" turns a missing database into a failure (CI).
	RequireEnv = "PC_TEST_REQUIRE_DB"
)

// templateLockKey serializes template creation across test processes.
const templateLockKey = 0x70635f746d706c // "pc_tmpl"

// DB is one disposable test database.
type DB struct {
	Name     string
	App      db.Config
	Migrator db.Config
	AuditRO  db.Config
	admin    *pgx.ConnConfig
}

type cluster struct {
	admin    *pgx.ConnConfig
	pw       db.RolePasswords
	template string
}

var (
	setupOnce sync.Once
	shared    *cluster
	errSetup  error
)

// New returns a fresh migrated database, dropped when the test ends. It skips
// the test when no admin URL is configured (fails when PC_TEST_REQUIRE_DB=1).
func New(t testing.TB) *DB {
	t.Helper()
	url := os.Getenv(AdminURLEnv)
	if url == "" {
		if os.Getenv(RequireEnv) == "1" {
			t.Fatalf("%s is required (%s=1)", AdminURLEnv, RequireEnv)
		}
		t.Skipf("set %s to run database integration tests (task up PROFILE=test)", AdminURLEnv)
	}
	setupOnce.Do(func() { shared, errSetup = setup(url) })
	if errSetup != nil {
		t.Fatalf("dbtest setup: %v", errSetup)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	name := "pc_test_" + randomHex(8)
	admin, err := pgx.ConnectConfig(ctx, shared.admin)
	if err != nil {
		t.Fatalf("dbtest: connect admin: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if err := execDDL(ctx, admin, "CREATE DATABASE %s TEMPLATE %s", name, shared.template); err != nil {
		t.Fatalf("dbtest: create database: %v", err)
	}
	t.Cleanup(func() { dropDatabase(context.Background(), shared.admin, name) })
	// Database-level ACLs are not copied from the template.
	if err := withDB(ctx, shared.admin, name, func(c *pgx.Conn) error { return db.BootstrapDatabase(ctx, c) }); err != nil {
		t.Fatalf("dbtest: bootstrap database: %v", err)
	}
	return &DB{
		Name:     name,
		App:      roleConfig(shared.admin, name, db.RoleApp, shared.pw.App, true),
		Migrator: roleConfig(shared.admin, name, db.RoleMigrator, shared.pw.Migrator, false),
		AuditRO:  roleConfig(shared.admin, name, db.RoleAuditRO, shared.pw.AuditRO, true),
		admin:    shared.admin,
	}
}

// AppPool opens a pool as pc_app, closed when the test ends.
func (d *DB) AppPool(t testing.TB) *db.Pool { return d.Pool(t, d.App) }

// Pool opens a pool with c, closed when the test ends.
func (d *DB) Pool(t testing.TB, c db.Config) *db.Pool {
	t.Helper()
	p, err := db.Open(context.Background(), c)
	if err != nil {
		t.Fatalf("dbtest: open pool as %s: %v", c.User, err)
	}
	t.Cleanup(p.Close)
	return p
}

// AdminExec runs a statement as the superuser in this database (for test
// setup that the application roles are deliberately not allowed to do).
func (d *DB) AdminExec(t testing.TB, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := withDB(ctx, d.admin, d.Name, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("dbtest: admin exec: %v", err)
	}
}

// AdminQueryRow runs a single-row query as the superuser in this database.
func (d *DB) AdminQueryRow(t testing.TB, sql string, args []any, dest ...any) {
	t.Helper()
	ctx := context.Background()
	if err := withDB(ctx, d.admin, d.Name, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, sql, args...).Scan(dest...)
	}); err != nil {
		t.Fatalf("dbtest: admin query: %v", err)
	}
}

// AdminConfig returns a superuser pool config for this database. Use it only
// to prove that privileged roles are refused.
func (d *DB) AdminConfig() db.Config {
	return roleConfig(d.admin, d.Name, d.admin.User, pclog.NewSecret([]byte(d.admin.Password)), false)
}

func setup(url string) (*cluster, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", AdminURLEnv, err)
	}
	if admin.Password == "" {
		return nil, fmt.Errorf("%s must include a password", AdminURLEnv)
	}
	c := &cluster{admin: admin, pw: db.RolePasswords{
		Migrator: derive(admin.Password, db.RoleMigrator),
		App:      derive(admin.Password, db.RoleApp),
		AuditRO:  derive(admin.Password, db.RoleAuditRO),
	}}
	conn, err := pgx.ConnectConfig(ctx, admin)
	if err != nil {
		return nil, fmt.Errorf("connect admin: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if err := db.BootstrapRoles(ctx, conn, c.pw); err != nil {
		return nil, err
	}
	c.template = "pc_tmpl_" + db.SchemaFingerprint()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(templateLockKey)); err != nil {
		return nil, err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(templateLockKey))
	}()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", c.template).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		if err := buildTemplate(ctx, conn, c); err != nil {
			dropDatabase(ctx, admin, c.template)
			return nil, err
		}
	}
	return c, nil
}

func buildTemplate(ctx context.Context, conn *pgx.Conn, c *cluster) error {
	// Remove templates of older schema fingerprints.
	rows, err := conn.Query(ctx, "SELECT datname FROM pg_database WHERE datname LIKE 'pc\\_tmpl\\_%' AND datname <> $1", c.template)
	if err != nil {
		return err
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, n := range old {
		dropDatabase(ctx, c.admin, n)
	}
	if err := execDDL(ctx, conn, "CREATE DATABASE %s", c.template); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	if err := withDB(ctx, c.admin, c.template, func(tc *pgx.Conn) error { return db.BootstrapDatabase(ctx, tc) }); err != nil {
		return err
	}
	if _, err := db.Migrate(ctx, roleConfig(c.admin, c.template, db.RoleMigrator, c.pw.Migrator, false)); err != nil {
		return err
	}
	return execDDL(ctx, conn, "ALTER DATABASE %s WITH IS_TEMPLATE true ALLOW_CONNECTIONS false", c.template)
}

func roleConfig(admin *pgx.ConnConfig, dbName, user string, pw pclog.Secret[[]byte], unprivileged bool) db.Config {
	c := db.Defaults()
	c.Host = admin.Host
	c.Port = int(admin.Port)
	c.Database = dbName
	c.User = user
	c.Password = pw
	c.SSLMode = "disable"
	c.MaxConns = 10
	c.ApplicationName = "pantherclaw-test"
	c.RequireUnprivileged = unprivileged
	return c
}

func withDB(ctx context.Context, admin *pgx.ConnConfig, name string, fn func(*pgx.Conn) error) error {
	cfg := admin.Copy()
	cfg.Database = name
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return fn(conn)
}

func dropDatabase(parent context.Context, admin *pgx.ConnConfig, name string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, admin)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if strings.HasPrefix(name, "pc_tmpl_") {
		_ = execDDL(ctx, conn, "ALTER DATABASE %s WITH IS_TEMPLATE false", name)
	}
	_ = execDDL(ctx, conn, "DROP DATABASE IF EXISTS %s WITH (FORCE)", name)
}

// execDDL runs a database-level DDL statement whose only variable parts are
// identifiers. PostgreSQL cannot bind identifiers as parameters, so each one
// is quoted with pgx.Identifier.Sanitize; the names are generated here, never
// taken from input.
func execDDL(ctx context.Context, conn *pgx.Conn, format string, idents ...string) error {
	quoted := make([]any, len(idents))
	for i, id := range idents {
		quoted[i] = pgx.Identifier{id}.Sanitize()
	}
	stmt := fmt.Sprintf(format, quoted...)
	_, err := conn.Exec(ctx, stmt) // nosemgrep
	return err
}

// derive returns a deterministic role password for the throwaway cluster, so
// concurrent test processes agree on it without coordination.
func derive(adminPassword, role string) pclog.Secret[[]byte] {
	m := hmac.New(sha256.New, []byte(adminPassword))
	m.Write([]byte("pc-test-role|" + role))
	return pclog.NewSecret([]byte(base64.RawURLEncoding.EncodeToString(m.Sum(nil))))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
