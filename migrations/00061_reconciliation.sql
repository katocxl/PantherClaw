-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Reconciliation (G0 M7 track A, design decisions 3, 4 and 6; HR-112,
-- HR-192, HR-193, HR-003, HR-007). Every unknown outcome opens a task that
-- keeps the transaction's reservations and dedupe claim held. Evidence
-- resolves it only towards OCCURRED; NOT_OCCURRED is a person's release,
-- kept with the WebAuthn assertion over the release binding and the basis
-- they wrote. A transaction link joins a later, separately authorized
-- transaction to an earlier one as its compensation or recovery, and
-- changes nothing about the earlier one. A target-log run compares what the
-- target created in a window with the execution receipts; an object without
-- one is an unreceipted effect, a finding for people, never an automatic
-- response.

-- +goose Up
CREATE TABLE pc.reconciliation_tasks (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    transaction_id     uuid        NOT NULL,
    kind               text        NOT NULL CHECK (kind IN ('unknown_outcome', 'conflicting_effect')),
    state              text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'OCCURRED', 'NOT_OCCURRED')),
    resolved_via       text        CHECK (resolved_via IN ('verifier', 'late_report', 'target_log', 'person')),
    observation_id     uuid,
    user_id            uuid,
    session_id         uuid,
    credential_id      uuid,
    authenticator_data bytea       CHECK (octet_length(authenticator_data) BETWEEN 37 AND 4096),
    client_data_json   bytea       CHECK (octet_length(client_data_json) BETWEEN 2 AND 4096),
    signature          bytea       CHECK (octet_length(signature) BETWEEN 1 AND 1024),
    basis              text        CHECK (char_length(basis) BETWEEN 1 AND 2000),
    evidence           uuid[]      CHECK (cardinality(evidence) <= 64),
    waitlist_entry_id  uuid,
    opened_at          timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, observation_id) REFERENCES pc.observations (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sessions (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, waitlist_entry_id) REFERENCES pc.waitlist_entries (org_id, id),
    CONSTRAINT reconciliation_tasks_resolved CHECK ((state = 'OPEN') = (resolved_at IS NULL)
                                                    AND (state = 'OPEN') = (resolved_via IS NULL)),
    -- Evidence resolves only towards OCCURRED, and names the observation.
    CONSTRAINT reconciliation_tasks_evidence CHECK (resolved_via IS NULL OR resolved_via = 'person'
                                                    OR (state = 'OCCURRED' AND observation_id IS NOT NULL)),
    -- A person resolves with a basis; releasing also needs a browser session
    -- and the WebAuthn assertion over the release binding (HR-192).
    CONSTRAINT reconciliation_tasks_person CHECK ((resolved_via = 'person') = (user_id IS NOT NULL)
                                                  AND (resolved_via IS DISTINCT FROM 'person' OR basis IS NOT NULL)),
    CONSTRAINT reconciliation_tasks_release CHECK ((state = 'NOT_OCCURRED') = (credential_id IS NOT NULL)
        AND (credential_id IS NULL) = (session_id IS NULL)
        AND (credential_id IS NULL) = (authenticator_data IS NULL)
        AND (credential_id IS NULL) = (client_data_json IS NULL)
        AND (credential_id IS NULL) = (signature IS NULL)),
    CONSTRAINT reconciliation_tasks_release_by_person CHECK (state <> 'NOT_OCCURRED' OR resolved_via = 'person')
);
-- At most one open task of each kind per transaction.
CREATE UNIQUE INDEX reconciliation_tasks_open ON pc.reconciliation_tasks (org_id, transaction_id, kind)
    WHERE state = 'OPEN';
CREATE INDEX reconciliation_tasks_state ON pc.reconciliation_tasks (org_id, state, opened_at);

-- A later transaction that compensates for, or recovers from, an earlier
-- one (HR-193). Insert-only.
CREATE TABLE pc.transaction_links (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    from_transaction_id uuid        NOT NULL,
    to_transaction_id   uuid        NOT NULL,
    kind                text        NOT NULL CHECK (kind IN ('compensates', 'recovers')),
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, from_transaction_id, to_transaction_id),
    FOREIGN KEY (org_id, from_transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, to_transaction_id) REFERENCES pc.transactions (org_id, id),
    CHECK (from_transaction_id <> to_transaction_id)
);
CREATE INDEX transaction_links_to ON pc.transaction_links (org_id, to_transaction_id);

-- The result of one target-log task (HR-112). Insert-only.
CREATE TABLE pc.target_log_runs (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    verification_id uuid        NOT NULL,
    connection_id   uuid        NOT NULL,
    window_start    timestamptz NOT NULL,
    window_end      timestamptz NOT NULL,
    items_seen      integer     NOT NULL CHECK (items_seen BETWEEN 0 AND 100000),
    matched         integer     NOT NULL CHECK (matched >= 0),
    unmatched       integer     NOT NULL CHECK (unmatched >= 0),
    complete        boolean     NOT NULL,
    finished_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, verification_id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK (window_start < window_end),
    CHECK (matched + unmatched <= items_seen)
);
CREATE INDEX target_log_runs_connection ON pc.target_log_runs (org_id, connection_id, window_end);

-- An object the target created that no execution receipt accounts for
-- (HR-112). A person acknowledges it; nothing else changes it.
CREATE TABLE pc.unreceipted_effects (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    connection_id     uuid        NOT NULL,
    operation         text        NOT NULL CHECK (char_length(operation) <= 128
                                                  AND operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    object_ref        text        NOT NULL CHECK (char_length(object_ref) BETWEEN 1 AND 256),
    correlation       text        CHECK (char_length(correlation) BETWEEN 1 AND 256),
    target_created_at timestamptz,
    verification_id   uuid        NOT NULL,
    state             text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ACKNOWLEDGED')),
    acknowledged_by   text        CHECK (char_length(acknowledged_by) BETWEEN 1 AND 100),
    acknowledged_at   timestamptz,
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, connection_id, object_ref),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK ((state = 'ACKNOWLEDGED') = (acknowledged_at IS NOT NULL)),
    CHECK ((acknowledged_at IS NULL) = (acknowledged_by IS NULL))
);
CREATE INDEX unreceipted_effects_open ON pc.unreceipted_effects (org_id, first_seen_at) WHERE state = 'OPEN';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['reconciliation_tasks', 'transaction_links', 'target_log_runs', 'unreceipted_effects']
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

GRANT SELECT, INSERT ON pc.reconciliation_tasks, pc.transaction_links, pc.target_log_runs, pc.unreceipted_effects
    TO pc_app;
-- A task changes once, from OPEN to its resolution; links and runs never change.
GRANT UPDATE (state, resolved_via, observation_id, user_id, session_id, credential_id, authenticator_data,
    client_data_json, signature, basis, evidence, waitlist_entry_id, resolved_at) ON pc.reconciliation_tasks TO pc_app;
GRANT UPDATE (state, acknowledged_by, acknowledged_at) ON pc.unreceipted_effects TO pc_app;
GRANT SELECT ON pc.reconciliation_tasks, pc.transaction_links, pc.target_log_runs, pc.unreceipted_effects
    TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.unreceipted_effects;
DROP TABLE pc.target_log_runs;
DROP TABLE pc.transaction_links;
DROP TABLE pc.reconciliation_tasks;
