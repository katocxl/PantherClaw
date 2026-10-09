-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agents (BUILD_GUIDE §8 M3, G0 M3): the inventory with one accountable
-- owner and one backup owner (F016, F574), the lifecycle state machine
-- (F020), the append-only change history (F024), gateway and scan
-- discoveries (F015, HR-148) and ADMISSION waitlist entries (PN-004.1).
-- Names bind nothing: agents are found by id only (F034, HR-147). State
-- changes are conditional updates (HR-004); agent_changes is insert-only for
-- pc_app. Discovery attributes are untrusted and stored only as observed.

-- +goose Up
CREATE TABLE pc.agents (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    purpose              text        NOT NULL DEFAULT '' CHECK (char_length(purpose) <= 2000),
    team_id              uuid,
    environment_id       uuid,
    owner_user_id        uuid,
    backup_owner_user_id uuid,
    execution_context    text        CHECK (execution_context IN ('desktop', 'ci', 'kubernetes', 'service')),
    state                text        NOT NULL CHECK (state IN ('DISCOVERED', 'CLAIMED', 'VERIFIED', 'OBSERVED',
                                                               'PARTIALLY_PROTECTED', 'PROTECTED', 'SUSPENDED', 'RETIRED')),
    suspended_from       text        CHECK (suspended_from IN ('DISCOVERED', 'CLAIMED', 'VERIFIED', 'OBSERVED',
                                                               'PARTIALLY_PROTECTED', 'PROTECTED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    claimed_at           timestamptz,
    retired_at           timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id),
    FOREIGN KEY (org_id, owner_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, backup_owner_user_id) REFERENCES pc.users (org_id, id),
    -- A claimed agent has its team, environment, owner and execution context;
    -- a discovered one has none of them yet.
    CONSTRAINT agents_claimed_is_complete CHECK (
        (claimed_at IS NULL AND team_id IS NULL AND environment_id IS NULL AND owner_user_id IS NULL
            AND backup_owner_user_id IS NULL AND execution_context IS NULL)
        OR (claimed_at IS NOT NULL AND team_id IS NOT NULL AND environment_id IS NOT NULL
            AND owner_user_id IS NOT NULL AND execution_context IS NOT NULL)),
    CONSTRAINT agents_discovered_is_unclaimed CHECK (state <> 'DISCOVERED' OR claimed_at IS NULL),
    CONSTRAINT agents_owner_differs_from_backup CHECK (backup_owner_user_id IS NULL OR backup_owner_user_id <> owner_user_id),
    CONSTRAINT agents_suspension_remembers_state CHECK ((state = 'SUSPENDED') = (suspended_from IS NOT NULL)),
    CONSTRAINT agents_retired_at CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE INDEX agents_state ON pc.agents (org_id, state);
CREATE INDEX agents_team ON pc.agents (org_id, team_id) WHERE team_id IS NOT NULL;

-- Append-only history (F024): who changed what and why. pc_app may only
-- insert and read.
CREATE TABLE pc.agent_changes (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    agent_id   uuid        NOT NULL,
    kind       text        NOT NULL CHECK (kind ~ '^[a-z][a-z_]{1,39}(\.[a-z][a-z_]{1,39}){0,2}$'),
    actor      text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 200),
    reason     text        NOT NULL DEFAULT '' CHECK (char_length(reason) <= 1000),
    details    jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'
                                                        AND octet_length(details::text) <= 16384),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id)
);
CREATE INDEX agent_changes_agent ON pc.agent_changes (org_id, agent_id, created_at);

-- A discovery is one unknown workload key seen at a gateway, or one local
-- scan finding, deduplicated per org (HR-148). observed holds untrusted
-- attributes (gateway, route, client address, user agent), shown as such.
CREATE TABLE pc.discoveries (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    agent_id      uuid        NOT NULL,
    source        text        NOT NULL CHECK (source IN ('gateway', 'scan')),
    key_jkt       text        CHECK (key_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    public_jwk    bytea       CHECK (octet_length(public_jwk) BETWEEN 2 AND 4096),
    scan_key      bytea       CHECK (octet_length(scan_key) = 32),
    state         text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CLAIMED', 'DISMISSED')),
    observed      jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(observed) = 'object'
                                                           AND octet_length(observed::text) <= 8192),
    seen_count    bigint      NOT NULL DEFAULT 1 CHECK (seen_count >= 1),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, key_jkt),
    UNIQUE (org_id, scan_key),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source = 'scan' AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL))
);
CREATE INDEX discoveries_open ON pc.discoveries (org_id) WHERE state = 'OPEN';

-- Agent Waitlist entries (PN-004.1). M3 creates ADMISSION entries only; M5
-- widens the kind CHECK. At most one open entry per subject.
CREATE TABLE pc.waitlist_entries (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('ADMISSION')),
    subject_type    text        NOT NULL CHECK (subject_type IN ('agent', 'instance')),
    subject_id      uuid        NOT NULL,
    agent_id        uuid        NOT NULL,
    state           text        NOT NULL DEFAULT 'OPEN'
                                CHECK (state IN ('OPEN', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
    evidence        jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'
                                                             AND octet_length(evidence::text) <= 16384),
    deadline_at     timestamptz NOT NULL,
    decided_by      text        CHECK (char_length(decided_by) BETWEEN 1 AND 100),
    decided_at      timestamptz,
    decision_reason text        NOT NULL DEFAULT '' CHECK (char_length(decision_reason) <= 1000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CONSTRAINT waitlist_entries_decided CHECK ((state = 'OPEN') = (decided_at IS NULL)),
    CONSTRAINT waitlist_entries_deadline CHECK (deadline_at > created_at)
);
CREATE UNIQUE INDEX waitlist_entries_one_open ON pc.waitlist_entries (org_id, subject_type, subject_id)
    WHERE state = 'OPEN';
CREATE INDEX waitlist_entries_open ON pc.waitlist_entries (org_id, kind, deadline_at) WHERE state = 'OPEN';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['agents', 'agent_changes', 'discoveries', 'waitlist_entries']
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

GRANT SELECT, INSERT ON pc.agents, pc.agent_changes, pc.discoveries, pc.waitlist_entries TO pc_app;
GRANT UPDATE (name, purpose, team_id, environment_id, owner_user_id, backup_owner_user_id, execution_context,
    state, suspended_from, updated_at, claimed_at, retired_at) ON pc.agents TO pc_app;
GRANT UPDATE (agent_id, state, observed, seen_count, last_seen_at) ON pc.discoveries TO pc_app;
GRANT UPDATE (state, decided_by, decided_at, decision_reason) ON pc.waitlist_entries TO pc_app;
GRANT SELECT ON pc.agents, pc.agent_changes, pc.discoveries, pc.waitlist_entries TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.waitlist_entries;
DROP TABLE pc.discoveries;
DROP TABLE pc.agent_changes;
DROP TABLE pc.agents;
