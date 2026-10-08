-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Grants for River's job tables (goose versions 2..9 are River's own
-- migrations, see migrations/river.go). River tables are global
-- infrastructure without org_id: job arguments carry IDs only (HR-056) and
-- tenant work happens inside per-org transactions (HR-054). pc_app gets DML
-- but never TRUNCATE (HR-055).

-- +goose Up
GRANT SELECT, INSERT, UPDATE, DELETE
    ON pc.river_job, pc.river_leader, pc.river_queue, pc.river_notification
    TO pc_app;
GRANT SELECT ON pc.river_migration TO pc_app;

-- +goose StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.oid::regclass AS seq
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'pc' AND c.relkind = 'S' AND c.relname LIKE 'river\_%'
    LOOP
        EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO pc_app', r.seq);
    END LOOP;
    FOR r IN
        SELECT p.oid::regprocedure AS fn
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'pc' AND p.proname LIKE 'river\_%'
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO pc_app', r.fn);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Down
REVOKE ALL ON pc.river_job, pc.river_leader, pc.river_queue, pc.river_notification,
    pc.river_migration FROM pc_app;
