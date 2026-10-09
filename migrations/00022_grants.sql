-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Grants and guardrails (G0 M4 part 2, design decisions 1-8): envelopes and
-- their immutable revisions; grants bound to an agent (by id, HR-147), a
-- represented principal and an environment, with immutable revisions; and
-- the lineage closure (each grant with every ancestor) that revocation
-- cascades through in one statement (HR-047). runs.grant_id gains its
-- foreign key, as 00019 anticipated, and pc_app may set it once when a
-- grant is delegated to a child run. State changes are conditional
-- (HR-004); revisions and lineage are insert-only.

-- +goose Up
CREATE TABLE pc.envelopes (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    scope_kind       text        NOT NULL CHECK (scope_kind IN ('org', 'business_unit', 'team', 'environment', 'principal')),
    -- scope_key names the scope: 'org', or '<kind>:<uuid>' (a principal is
    -- 'user:<uuid>' or 'service_account:<uuid>').
    scope_key        text        NOT NULL CHECK (scope_key ~ '^(org|(business_unit|team|environment|user|service_account):[0-9a-f-]{36})$'),
    current_revision integer     NOT NULL CHECK (current_revision > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, scope_key)
);

CREATE TABLE pc.envelope_revisions (
    org_id              uuid        NOT NULL,
    id                  uuid        NOT NULL,
    envelope_id         uuid        NOT NULL,
    revision            integer     NOT NULL CHECK (revision > 0),
    name                text        NOT NULL CHECK (char_length(name) <= 100),
    bounds              bytea       NOT NULL CHECK (octet_length(bounds) BETWEEN 2 AND 65536),
    requirements        bytea       NOT NULL CHECK (octet_length(requirements) BETWEEN 2 AND 65536),
    limits              bytea       NOT NULL CHECK (octet_length(limits) BETWEEN 2 AND 65536),
    max_depth           smallint    CHECK (max_depth BETWEEN 0 AND 4),
    max_children        smallint    CHECK (max_children BETWEEN 0 AND 50),
    max_root_lifetime_s bigint      CHECK (max_root_lifetime_s BETWEEN 60 AND 7776000),
    repeat_window_s     bigint      CHECK (repeat_window_s BETWEEN 3600 AND 2592000),
    min_attestation     smallint    NOT NULL DEFAULT 0 CHECK (min_attestation BETWEEN 0 AND 2),
    widens              boolean     NOT NULL,
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, envelope_id, revision),
    FOREIGN KEY (org_id, envelope_id) REFERENCES pc.envelopes (org_id, id)
);

CREATE TABLE pc.grants (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    agent_id           uuid        NOT NULL,
    instance_id        uuid,
    principal_user_id  uuid,
    principal_sa_id    uuid,
    environment_id     uuid        NOT NULL,
    parent_id          uuid,
    depth              smallint    NOT NULL CHECK (depth BETWEEN 0 AND 4),
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    current_revision   integer     NOT NULL CHECK (current_revision > 0),
    grantor_kind       text        NOT NULL CHECK (grantor_kind IN ('user', 'service_account', 'instance')),
    grantor_id         uuid        NOT NULL,
    basis              text        NOT NULL CHECK (char_length(basis) BETWEEN 1 AND 256),
    -- children_total counts every grant ever delegated from this one; it is
    -- updated with the parent's row locked, so the lifetime cap holds.
    children_total     integer     NOT NULL DEFAULT 0 CHECK (children_total BETWEEN 0 AND 100),
    created_at         timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz,
    revoke_reason      text        CHECK (char_length(revoke_reason) BETWEEN 1 AND 256),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, principal_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, principal_sa_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id),
    FOREIGN KEY (org_id, parent_id) REFERENCES pc.grants (org_id, id),
    CONSTRAINT grants_one_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id) = 1),
    CONSTRAINT grants_lineage CHECK ((parent_id IS NULL) = (depth = 0)),
    -- Only people issue root grants (HR-161, decision 7); a delegated grant
    -- is issued by the parent run's instance or revised by a person.
    CONSTRAINT grants_root_by_a_person CHECK (parent_id IS NOT NULL OR grantor_kind = 'user'),
    CONSTRAINT grants_revoked CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);
CREATE INDEX grants_children ON pc.grants (org_id, parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX grants_agent ON pc.grants (org_id, agent_id);

CREATE TABLE pc.grant_revisions (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    grant_id         uuid        NOT NULL,
    revision         integer     NOT NULL CHECK (revision > 0),
    task_ref         text        NOT NULL DEFAULT '' CHECK (char_length(task_ref) <= 256),
    not_before       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    bounds           bytea       NOT NULL CHECK (octet_length(bounds) BETWEEN 2 AND 65536),
    requirements     bytea       NOT NULL CHECK (octet_length(requirements) BETWEEN 2 AND 65536),
    limits           bytea       NOT NULL CHECK (octet_length(limits) BETWEEN 2 AND 65536),
    delegation_depth smallint    NOT NULL CHECK (delegation_depth BETWEEN 0 AND 4),
    max_children     smallint    NOT NULL CHECK (max_children BETWEEN 0 AND 50),
    min_attestation  smallint    NOT NULL CHECK (min_attestation BETWEEN 0 AND 2),
    widens           boolean     NOT NULL,
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, grant_id, revision),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    CONSTRAINT grant_revisions_window CHECK (not_before < expires_at)
);

-- grant_lineage holds (grant, ancestor, distance) for the grant itself
-- (distance 0) and every ancestor, so a cascade is one indexed lookup.
CREATE TABLE pc.grant_lineage (
    org_id      uuid     NOT NULL,
    grant_id    uuid     NOT NULL,
    ancestor_id uuid     NOT NULL,
    distance    smallint NOT NULL CHECK (distance BETWEEN 0 AND 4),
    PRIMARY KEY (org_id, grant_id, ancestor_id),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    FOREIGN KEY (org_id, ancestor_id) REFERENCES pc.grants (org_id, id)
);
CREATE INDEX grant_lineage_descendants ON pc.grant_lineage (org_id, ancestor_id);

ALTER TABLE pc.runs ADD CONSTRAINT runs_grant_fk FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['envelopes', 'envelope_revisions', 'grants', 'grant_revisions', 'grant_lineage']
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

GRANT SELECT, INSERT ON pc.envelopes, pc.envelope_revisions, pc.grants, pc.grant_revisions, pc.grant_lineage TO pc_app;
GRANT UPDATE (current_revision) ON pc.envelopes TO pc_app;
GRANT UPDATE (state, current_revision, children_total, revoked_at, revoke_reason) ON pc.grants TO pc_app;
GRANT UPDATE (grant_id) ON pc.runs TO pc_app;
GRANT SELECT ON pc.envelope_revisions, pc.grants, pc.grant_revisions, pc.grant_lineage TO pc_audit_ro;

-- +goose Down
REVOKE UPDATE (grant_id) ON pc.runs FROM pc_app;
ALTER TABLE pc.runs DROP CONSTRAINT runs_grant_fk;
DROP TABLE pc.grant_lineage;
DROP TABLE pc.grant_revisions;
DROP TABLE pc.grants;
DROP TABLE pc.envelope_revisions;
DROP TABLE pc.envelopes;
