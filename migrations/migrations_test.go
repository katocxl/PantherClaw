// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var fileName = regexp.MustCompile(`^(\d{5})_[a-z0-9_]+\.sql$`)

func sqlVersions(t *testing.T) []int64 {
	t.Helper()
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var out []int64
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			t.Errorf("migration file %q does not match NNNNN_name.sql", e.Name())
			continue
		}
		v, _ := strconv.ParseInt(m[1], 10, 64)
		out = append(out, v)
	}
	return out
}

func TestRiverMigrationsAreAllMapped(t *testing.T) {
	m, err := riverMigrator()
	if err != nil {
		t.Fatal(err)
	}
	var mapped []int
	for _, v := range riverVersions {
		mapped = append(mapped, v.River)
	}
	for _, rm := range m.AllVersions() {
		if !slices.Contains(mapped, rm.Version) {
			t.Errorf("River migration %d (%s) is not mapped to a goose version: append it to riverVersions", rm.Version, rm.Name)
		}
	}
	files := sqlVersions(t)
	var last int64
	for i, v := range riverVersions {
		if slices.Contains(files, v.Goose) {
			t.Errorf("goose version %d is used by both a SQL file and River %d", v.Goose, v.River)
		}
		if v.Goose <= last || (i > 0 && v.River != riverVersions[i-1].River+1) {
			t.Errorf("riverVersions must increase in both goose and River order (entry %d)", i)
		}
		last = v.Goose
	}
}

func TestGoMigrationsRender(t *testing.T) {
	gm, err := Go()
	if err != nil {
		t.Fatal(err)
	}
	if len(gm) != len(riverVersions) {
		t.Fatalf("got %d Go migrations, want %d", len(gm), len(riverVersions))
	}
	if _, err := renderRiverSQL("SELECT 1 FROM /* TEMPLATE: other */x"); err == nil {
		t.Fatal("unknown template marker accepted")
	}
	got, err := renderRiverSQL("CREATE TABLE /* TEMPLATE: schema */river_job ()")
	if err != nil || got != "CREATE TABLE pc.river_job ()" {
		t.Fatalf("render = %q, %v", got, err)
	}
	fp1, err1 := Fingerprint()
	fp2, err2 := Fingerprint()
	if err1 != nil || err2 != nil || fp1 != fp2 || len(fp1) != 64 {
		t.Fatalf("fingerprint unstable: %s %s %v %v", fp1, fp2, err1, err2)
	}
}

func TestSQLMigrationsFollowConventions(t *testing.T) {
	entries, _ := fs.ReadDir(FS, ".")
	for _, e := range entries {
		b, err := fs.ReadFile(FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{"-- +goose Up", "-- +goose Down"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", e.Name(), want)
			}
		}
		// Plain SET of the tenant setting is banned (HR-051); set_config only.
		if regexp.MustCompile(`(?i)\bSET\s+(LOCAL\s+)?app\.`).MatchString(s) {
			t.Errorf("%s: sets app.* with SET; use set_config (HR-051)", e.Name())
		}
		// Every created table lives in schema pc.
		for _, m := range regexp.MustCompile(`(?i)CREATE\s+(UNLOGGED\s+)?TABLE\s+(IF NOT EXISTS\s+)?([a-z0-9_."]+)`).FindAllStringSubmatch(s, -1) {
			if !strings.HasPrefix(m[3], "pc.") {
				t.Errorf("%s: table %s is not schema-qualified with pc.", e.Name(), m[3])
			}
		}
	}
}
