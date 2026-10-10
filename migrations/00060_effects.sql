-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Effects (G0 M7 track A, design decisions 1-3, HR-190..192, PAP-1 §9.2,
-- §9.3). An execution receipt's JWS is now kept (until M7 only its hash
-- reached the ledger), and an attempt records who wrote it: the gateway, or
-- the sweeper for a dispatch that never reported. A verification is a task
-- the server leases to the gateway serving the connection, which reads the
-- target through a reviewed read operation and reports an observation.
-- Observations and effect receipts are append-only; a transaction keeps
-- only its current effect state and levels, which every new effect receipt
-- states again.

-- +goose Up
ALTER TABLE pc.execution_attempts
    ADD COLUMN recorded_by text NOT NULL DEFAULT 'gateway' CHECK (recorded_by IN ('gateway', 'sweeper')),
    ADD COLUMN target_ref  text CHECK (target_ref IS NULL OR char_length(target_ref) BETWEEN 1 AND 256),
    -- The sweeper records only an unknown outcome, and never a target's answer.
    ADD CONSTRAINT execution_attempts_sweeper CHECK (recorded_by = 'gateway' OR
        (outcome = 'unknown' AND target_status IS NULL AND response_digest IS NULL AND target_ref IS NULL));

ALTER TABLE pc.transactions
    ADD COLUMN effect_state          text CHECK (effect_state IN ('CONFIRMED', 'NONE_CONFIRMED', 'PARTIAL',
        'PROPAGATION_PENDING', 'CONFLICTING', 'UNVERIFIABLE', 'UNKNOWN', 'COMPENSATED')),
    ADD COLUMN effect_level_required text CHECK (effect_level_required IN ('acceptance', 'follow_up', 'domain_effect', 'downstream')),
    ADD COLUMN effect_level_achieved text CHECK (effect_level_achieved IN ('acceptance', 'follow_up', 'domain_effect', 'downstream')),
    ADD CONSTRAINT transactions_effect CHECK (effect_state IS NOT NULL OR effect_level_achieved IS NULL);

-- The signed execution receipt of one attempt (PAP-1 §9.2).
CREATE TABLE pc.execution_receipts (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    attempt_id      uuid        NOT NULL,
    transaction_id  uuid        NOT NULL,
    permit_id       uuid        NOT NULL,
    receipt_jws     text        NOT NULL CHECK (char_length(receipt_jws) BETWEEN 16 AND 65536),
    ledger_entry_id uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, attempt_id),
    UNIQUE (org_id, permit_id),
    FOREIGN KEY (org_id, attempt_id) REFERENCES pc.execution_attempts (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, permit_id) REFERENCES pc.permits (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id)
);

-- A verification task (HR-190). request holds the read the server computed
-- (operation target and parameters); nothing in it comes from the agent
-- except through the reviewed mapping. A lease is single use: the gateway
-- holds the secret, the row only its SHA-256, and a lease that expires
-- unreported returns the task to PENDING. A target-log task lists objects
-- created in its window and belongs to no transaction.
CREATE TABLE pc.verifications (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    purpose          text        NOT NULL CHECK (purpose IN ('follow_up', 'reconcile', 'target_log')),
    transaction_id   uuid,
    connection_id    uuid        NOT NULL,
    operation        text        NOT NULL CHECK (char_length(operation) <= 128 AND operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    request          jsonb       NOT NULL CHECK (jsonb_typeof(request) = 'object' AND octet_length(request::text) <= 8192),
    state            text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'LEASED', 'DONE', 'EXPIRED', 'CANCELLED')),
    attempts         integer     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
    next_at          timestamptz NOT NULL,
    deadline_at      timestamptz NOT NULL,
    window_start     timestamptz,
    window_end       timestamptz,
    lease_hash       bytea       CHECK (lease_hash IS NULL OR octet_length(lease_hash) = 32),
    leased_by        uuid,
    leased_at        timestamptz,
    lease_expires_at timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, leased_by) REFERENCES pc.gateways (org_id, id),
    CHECK ((purpose = 'target_log') = (transaction_id IS NULL)),
    CHECK ((purpose = 'target_log') = (window_start IS NOT NULL AND window_end IS NOT NULL)),
    CHECK (window_start IS NULL OR window_start < window_end),
    CHECK (deadline_at > created_at),
    CHECK ((state = 'LEASED') = (lease_hash IS NOT NULL AND leased_by IS NOT NULL AND leased_at IS NOT NULL
        AND lease_expires_at IS NOT NULL)),
    -- A lease lasts at most 30 seconds (HR-190).
    CHECK (lease_expires_at IS NULL OR (lease_expires_at > leased_at AND lease_expires_at <= leased_at + interval '30 seconds')),
    CHECK ((state IN ('DONE', 'EXPIRED', 'CANCELLED')) = (finished_at IS NOT NULL))
);
-- At most one open task per transaction and purpose.
CREATE UNIQUE INDEX verifications_open ON pc.verifications (org_id, transaction_id, purpose)
    WHERE state IN ('PENDING', 'LEASED') AND transaction_id IS NOT NULL;
CREATE UNIQUE INDEX verifications_lease ON pc.verifications (org_id, lease_hash) WHERE lease_hash IS NOT NULL;
CREATE INDEX verifications_due ON pc.verifications (org_id, connection_id, next_at) WHERE state = 'PENDING';
CREATE INDEX verifications_transaction ON pc.verifications (org_id, transaction_id) WHERE transaction_id IS NOT NULL;

-- What one source observed (HR-190, HR-191): a verifier read, a gateway's
-- late report after the sweeper, or a target-log listing. fields holds only
-- the fields the verifier declares, never a response body.
CREATE TABLE pc.observations (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    source          text        NOT NULL CHECK (source IN ('verifier', 'late_report', 'target_log')),
    transaction_id  uuid,
    verification_id uuid,
    gateway_id      uuid        NOT NULL,
    attempt         integer     CHECK (attempt IS NULL OR attempt BETWEEN 1 AND 1000),
    http_status     integer     CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    outcome         text        CHECK (outcome IS NULL OR outcome IN ('accepted', 'failed', 'unknown')),
    found           boolean,
    complete        boolean,
    fields          jsonb       CHECK (fields IS NULL OR (jsonb_typeof(fields) = 'object' AND octet_length(fields::text) <= 16384)),
    response_digest bytea       CHECK (response_digest IS NULL OR octet_length(response_digest) = 32),
    observed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    CHECK ((source = 'late_report') = (verification_id IS NULL)),
    CHECK ((source = 'late_report') = (outcome IS NOT NULL)),
    CHECK (source <> 'late_report' OR transaction_id IS NOT NULL),
    CHECK (source = 'target_log' OR complete IS NULL)
);
CREATE INDEX observations_transaction ON pc.observations (org_id, transaction_id, observed_at) WHERE transaction_id IS NOT NULL;
CREATE INDEX observations_verification ON pc.observations (org_id, verification_id) WHERE verification_id IS NOT NULL;

-- One signed effect receipt per change of a transaction's effect state
-- (HR-191, PAP-1 §9.3), appended, never rewritten.
CREATE TABLE pc.effect_receipts (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    transaction_id  uuid        NOT NULL,
    seq             integer     NOT NULL CHECK (seq BETWEEN 1 AND 1000),
    state           text        NOT NULL CHECK (state IN ('CONFIRMED', 'NONE_CONFIRMED', 'PARTIAL',
        'PROPAGATION_PENDING', 'CONFLICTING', 'UNVERIFIABLE', 'UNKNOWN', 'COMPENSATED')),
    level_required  text        NOT NULL CHECK (level_required IN ('acceptance', 'follow_up', 'domain_effect', 'downstream')),
    level_achieved  text        CHECK (level_achieved IN ('acceptance', 'follow_up', 'domain_effect', 'downstream')),
    basis           text        NOT NULL CHECK (basis IN ('verifier', 'late_report', 'target_log', 'person', 'compensation',
        'definition', 'deadline')),
    receipt_jws     text        NOT NULL CHECK (char_length(receipt_jws) BETWEEN 16 AND 65536),
    ledger_entry_id uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id, seq),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['execution_receipts', 'verifications', 'observations', 'effect_receipts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- Receipts and observations are evidence: no UPDATE or DELETE (HR-055).
GRANT SELECT, INSERT ON pc.execution_receipts, pc.verifications, pc.observations, pc.effect_receipts TO pc_app;
GRANT UPDATE (state, attempts, next_at, lease_hash, leased_by, leased_at, lease_expires_at, finished_at)
    ON pc.verifications TO pc_app;
GRANT UPDATE (effect_state, effect_level_required, effect_level_achieved) ON pc.transactions TO pc_app;
GRANT SELECT ON pc.execution_receipts, pc.observations, pc.effect_receipts TO pc_audit_ro;
-- Never the lease hash.
GRANT SELECT (org_id, id, purpose, transaction_id, connection_id, operation, request, state, attempts, next_at,
    deadline_at, window_start, window_end, leased_by, leased_at, lease_expires_at, created_at, finished_at)
    ON pc.verifications TO pc_audit_ro;

-- The worker finds orgs whose tasks passed their deadline or whose leases
-- expired; gateways lease due tasks themselves.
GRANT SELECT (org_id, state, deadline_at, lease_expires_at) ON pc.verifications TO pc_lister;

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
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
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
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
REVOKE SELECT (org_id, state, deadline_at, lease_expires_at) ON pc.verifications FROM pc_lister;
REVOKE UPDATE (effect_state, effect_level_required, effect_level_achieved) ON pc.transactions FROM pc_app;
DROP TABLE pc.effect_receipts;
DROP TABLE pc.observations;
DROP TABLE pc.verifications;
DROP TABLE pc.execution_receipts;
ALTER TABLE pc.transactions DROP CONSTRAINT transactions_effect, DROP COLUMN effect_level_achieved,
    DROP COLUMN effect_level_required, DROP COLUMN effect_state;
ALTER TABLE pc.execution_attempts DROP CONSTRAINT execution_attempts_sweeper, DROP COLUMN target_ref,
    DROP COLUMN recorded_by;
