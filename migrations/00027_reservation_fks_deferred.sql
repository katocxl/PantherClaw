-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A reservation's account and counter foreign keys are checked at COMMIT
-- (HR-048). Checked at INSERT, each finalization took FOR KEY SHARE on the
-- hot budget and counter rows before its conditional updates, so the rows'
-- xmax became a multixact of every finalization in flight. When one of them
-- updated a row and then rolled back (a later row was exhausted),
-- PostgreSQL 17 could build a multixact with two updating members and fail
-- the next update with "new multixact has more than one updating member"
-- (XX000): the conflict check already sees the abort in pg_xact while
-- MultiXactIdExpand still finds the transaction in the ProcArray. Checked at
-- COMMIT, a finalization locks only row versions it has itself updated, so
-- no other transaction holds a lock on a hot row while it is updated.

-- +goose Up
ALTER TABLE pc.reservations
    ALTER CONSTRAINT reservations_org_id_account_id_fkey DEFERRABLE INITIALLY DEFERRED,
    ALTER CONSTRAINT reservations_org_id_counter_id_fkey DEFERRABLE INITIALLY DEFERRED;

-- +goose Down
ALTER TABLE pc.reservations
    ALTER CONSTRAINT reservations_org_id_account_id_fkey NOT DEFERRABLE,
    ALTER CONSTRAINT reservations_org_id_counter_id_fkey NOT DEFERRABLE;
