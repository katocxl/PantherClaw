// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Worktrees on branches with different migrations run their tests against one
// cluster at the same time. Starting a run must not drop a template that
// another run may still be cloning, but templates nobody uses are dropped
// eventually.
func TestTemplatesOfDifferentFingerprintsCoexist(t *testing.T) {
	New(t) // builds or reuses this fingerprint's template
	ctx := t.Context()
	conn, err := pgx.ConnectConfig(ctx, shared.admin)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	// Another worktree starts its run and builds the template for its own
	// fingerprint (the same migrations under another name).
	other := *shared
	other.template = "pc_tmpl_test" + randomHex(4)
	t.Cleanup(func() { dropDatabase(context.Background(), shared.admin, other.template) })
	now := time.Now()
	if err := prepareTemplate(ctx, conn, &other, now); err != nil {
		t.Fatalf("prepare the other template: %v", err)
	}

	// Both templates survive and can be cloned.
	New(t)
	clone := "pc_test_" + randomHex(8)
	if err := execDDL(ctx, conn, "CREATE DATABASE %s TEMPLATE %s", clone, other.template); err != nil {
		t.Fatalf("clone the other template: %v", err)
	}
	dropDatabase(ctx, shared.admin, clone)

	// A template built before last-used marks existed.
	unmarked := "pc_tmpl_test" + randomHex(4)
	if err := execDDL(ctx, conn, "CREATE DATABASE %s", unmarked); err != nil {
		t.Fatalf("create unmarked template: %v", err)
	}
	t.Cleanup(func() { dropDatabase(context.Background(), shared.admin, unmarked) })

	// Nobody has started a run with the other fingerprint for longer than
	// templateTTL: the next run of any fingerprint drops its template, and
	// starts the clock on the unmarked one instead of dropping it.
	if err := markUsed(ctx, conn, other.template, now.Add(-templateTTL-time.Minute)); err != nil {
		t.Fatalf("mark the other template stale: %v", err)
	}
	if err := prepareTemplate(ctx, conn, shared, now); err != nil {
		t.Fatalf("prepare this template: %v", err)
	}
	for name, want := range map[string]bool{shared.template: true, other.template: false, unmarked: true} {
		if got, err := databaseExists(ctx, conn, name); err != nil || got != want {
			t.Errorf("database %s exists = %v (err %v), want %v", name, got, err, want)
		}
	}
	var comment string
	if err := conn.QueryRow(ctx, "SELECT coalesce(shobj_description(oid, 'pg_database'), '') FROM pg_database WHERE datname = $1",
		unmarked).Scan(&comment); err != nil {
		t.Fatalf("read the unmarked template's comment: %v", err)
	}
	if _, ok := parseLastUsed(comment); !ok {
		t.Errorf("unmarked template has comment %q, want a last-used mark", comment)
	}
	New(t)
}
