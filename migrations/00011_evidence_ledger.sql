-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Evidence ledger, part 1 (ADR-0009, HR-110 groundwork). Entries (receipts,
-- platform audit events) are inserted unchained inside their business
-- transaction, stamped with the inserting transaction's id. A per-org
-- chainer later links entries whose xid is below pg_snapshot_xmin into the
-- insert-only ledger_chain:
--   entry_hash = SHA-256(prev_hash || canonical(entry, seq))
-- Entries and links are append-only for pc_app (HR-055).

-- +goose Up
CREATE TABLE pc.ledger_entries (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    kind         text        NOT NULL CHECK (char_length(kind) <= 128 AND kind ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'),
    actor_type   text        NOT NULL CHECK (char_length(actor_type) BETWEEN 1 AND 32),
    actor_id     text        NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 256),
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    body         bytea       NOT NULL CHECK (octet_length(body) BETWEEN 2 AND 65536),
    xid          xid8        NOT NULL DEFAULT pg_current_xact_id(),
    PRIMARY KEY (org_id, id)
);
CREATE INDEX ledger_entries_by_xid ON pc.ledger_entries (org_id, xid, id);

CREATE TABLE pc.ledger_chain (
    org_id      uuid        NOT NULL,
    seq         bigint      NOT NULL CHECK (seq > 0),
    entry_id    uuid        NOT NULL,
    prev_hash   bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash  bytea       NOT NULL CHECK (octet_length(entry_hash) = 32),
    chained_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, seq),
    UNIQUE (org_id, entry_id),
    FOREIGN KEY (org_id, entry_id) REFERENCES pc.ledger_entries (org_id, id)
);

-- One mutable row per org: the chain head and the xid watermark below which
-- every committed entry is chained. It can be rebuilt from ledger_chain.
CREATE TABLE pc.ledger_heads (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    seq            bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    head_hash      bytea       NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
                               CHECK (octet_length(head_hash) = 32),
    xid_watermark  xid8        NOT NULL DEFAULT '0',
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

ALTER TABLE pc.ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.ledger_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.ledger_entries
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

ALTER TABLE pc.ledger_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.ledger_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.ledger_chain
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

ALTER TABLE pc.ledger_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.ledger_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.ledger_heads
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- Append-only evidence: no UPDATE, DELETE or TRUNCATE for pc_app (HR-055).
GRANT SELECT, INSERT ON pc.ledger_entries, pc.ledger_chain TO pc_app;
GRANT SELECT, INSERT, UPDATE ON pc.ledger_heads TO pc_app;
GRANT SELECT ON pc.ledger_entries, pc.ledger_chain, pc.ledger_heads TO pc_audit_ro;

-- The chainer dispatcher finds orgs with entries above their watermark
-- through the audited lister (HR-054).
GRANT SELECT (org_id, id, xid) ON pc.ledger_entries TO pc_lister;
GRANT SELECT (org_id, xid_watermark) ON pc.ledger_heads TO pc_lister;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
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
        WHEN 'ledger_unchained' THEN
            -- One row per org that has entries above its chain watermark; the
            -- id column repeats the org id.
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
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
DROP TABLE pc.ledger_heads;
DROP TABLE pc.ledger_chain;
DROP TABLE pc.ledger_entries;
