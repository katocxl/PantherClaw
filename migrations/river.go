// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

type pgxTx = pgx.Tx

// River's own SQL migrations (MPL-2.0, shipped inside the River module) are
// applied through goose so that the whole schema has one history
// (ARCHITECTURE §7, ADR-0006). They are rendered at migration time from the
// pinned River module, never copied into this repository.
//
// riverVersions maps goose versions to River main-line migration versions.
// When a River upgrade adds a migration, append it with the next free goose
// version; TestRiverMigrationsAreAllMapped fails until that is done.
var riverVersions = []struct {
	Goose int64
	River int
}{
	{2, 1}, {3, 2}, {4, 3}, {5, 4}, {6, 5}, {7, 6}, {8, 7}, {9, 8},
}

const (
	riverSchemaTemplate = "/* TEMPLATE: schema */"
	riverSchema         = "pc."
	// River 005 rebuilds river_migration with a (line, version) key.
	riverLineVersion = 5
)

// Go returns the Go-defined migrations (River's) for the goose provider.
func Go() ([]*goose.Migration, error) {
	m, err := riverMigrator()
	if err != nil {
		return nil, err
	}
	out := make([]*goose.Migration, 0, len(riverVersions))
	for _, v := range riverVersions {
		rm, err := m.GetVersion(v.River)
		if err != nil {
			return nil, fmt.Errorf("migrations: river %d: %w", v.River, err)
		}
		up, err := renderRiverSQL(rm.SQLUp)
		if err != nil {
			return nil, fmt.Errorf("migrations: river %d up: %w", v.River, err)
		}
		down, err := renderRiverSQL(rm.SQLDown)
		if err != nil {
			return nil, fmt.Errorf("migrations: river %d down: %w", v.River, err)
		}
		out = append(out, goose.NewGoMigration(v.Goose,
			&goose.GoFunc{RunTx: riverUp(v.River, up)},
			&goose.GoFunc{RunTx: riverDown(v.River, down)},
		))
	}
	return out, nil
}

// Fingerprint identifies the Go-defined migrations (version mapping plus
// rendered River SQL) for test template naming.
func Fingerprint() (string, error) {
	m, err := riverMigrator()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, v := range riverVersions {
		rm, err := m.GetVersion(v.River)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%d:%d\x00%s\x00%s\x00", v.Goose, v.River, rm.SQLUp, rm.SQLDown)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func riverMigrator() (*rivermigrate.Migrator[pgxTx], error) {
	// A driver without a pool is enough to read River's embedded migrations.
	return rivermigrate.New(riverpgxv5.New(nil), &rivermigrate.Config{Schema: "pc"})
}

// renderRiverSQL substitutes the schema placeholder the same way River's own
// migrator does, and refuses any other template marker.
func renderRiverSQL(s string) (string, error) {
	s = strings.ReplaceAll(s, riverSchemaTemplate, riverSchema)
	if strings.Contains(s, "/* TEMPLATE") {
		return "", fmt.Errorf("unsupported template marker in River SQL")
	}
	return s, nil
}

// riverUp applies one River migration and records it in River's own
// river_migration table, as River's migrator would, so River tooling sees a
// consistent state.
func riverUp(version int, sqlText string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, sqlText); err != nil {
			return fmt.Errorf("river migration %03d: %w", version, err)
		}
		record := "INSERT INTO pc.river_migration (version) VALUES ($1)"
		if version >= riverLineVersion {
			record = "INSERT INTO pc.river_migration (line, version) VALUES ('main', $1)"
		}
		if _, err := tx.ExecContext(ctx, record, version); err != nil {
			return fmt.Errorf("river migration %03d: record version: %w", version, err)
		}
		return nil
	}
}

func riverDown(version int, sqlText string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if version > 1 {
			del := "DELETE FROM pc.river_migration WHERE version = $1"
			if version >= riverLineVersion {
				del = "DELETE FROM pc.river_migration WHERE line = 'main' AND version = $1"
			}
			if _, err := tx.ExecContext(ctx, del, version); err != nil {
				return fmt.Errorf("river migration %03d down: forget version: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, sqlText); err != nil {
			return fmt.Errorf("river migration %03d down: %w", version, err)
		}
		return nil
	}
}
