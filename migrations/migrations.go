// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package migrations embeds the goose SQL migrations (BUILD_GUIDE §3.3).
//
// Rules: files are NNNNN_name.sql with "-- +goose Up" and "-- +goose Down"
// sections; merged migrations are never edited; every object lives in schema
// pc; every tenant table is RLS ENABLEd and FORCEd with the standard policy
// (HR-050..053); grants to pc_app are explicit per table.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
