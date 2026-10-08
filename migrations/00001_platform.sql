-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Platform root: organizations (tenant root, RLS on id) and the single audited
-- cross-org lister (HR-050..054). Runs as pc_migrator in schema pc.

-- +goose Up
CREATE TABLE pc.orgs (
    id          uuid        PRIMARY KEY,
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'SUSPENDED', 'DELETED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE pc.orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.orgs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.orgs
    USING (id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT, UPDATE ON pc.orgs TO pc_app;
GRANT SELECT ON pc.orgs TO pc_audit_ro;

-- The reserved platform org owns platform-level evidence (licence changes,
-- platform key events). Tenant context is set for this insert because RLS
-- is forced even for the table owner.
SELECT set_config('app.org_id', '00000000-0000-7000-8000-000000000001', true);
INSERT INTO pc.orgs (id, name) VALUES ('00000000-0000-7000-8000-000000000001', 'PantherClaw platform');
SELECT set_config('app.org_id', '', true);

-- Every call of the cross-org lister is recorded here (HR-054). Global table:
-- no org_id, no access for pc_app.
CREATE TABLE pc.cross_org_list_audit (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    purpose    text        NOT NULL,
    max_rows   integer     NOT NULL,
    caller     text        NOT NULL,
    called_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON pc.cross_org_list_audit TO pc_audit_ro;
GRANT INSERT ON pc.cross_org_list_audit TO pc_lister;

-- The one SECURITY DEFINER function (HR-053). It runs as pc_lister
-- (BYPASSRLS, minimal column grants), returns only (org_id, id) pairs from
-- static per-purpose queries (no dynamic SQL), pins search_path, and audits
-- every call. New purposes are added by later migrations with
-- CREATE OR REPLACE.
-- +goose StatementBegin
CREATE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

GRANT SELECT (id, state) ON pc.orgs TO pc_lister;
ALTER FUNCTION pc.cross_org_list(text, integer) OWNER TO pc_lister;
REVOKE ALL ON FUNCTION pc.cross_org_list(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pc.cross_org_list(text, integer) TO pc_app;

-- +goose Down
DROP FUNCTION pc.cross_org_list(text, integer);
DROP TABLE pc.cross_org_list_audit;
DROP TABLE pc.orgs;
