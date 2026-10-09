-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Runs (PAP-1 §5, HR-022, HR-146, G0 M3): minted only by the Authority and
-- bound to an agent, optionally one instance (bound at first use when not
-- given), the launcher and the represented principal. Exactly one launcher
-- column and one principal column are set, each a foreign key. A principal
-- from a subject token records the provider identity (iss, sub). Child runs
-- nest at most 8 deep. M3 runs carry no grant; grant_id gains its foreign
-- key and becomes required in M4.

-- +goose Up
CREATE TABLE pc.runs (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    agent_id             uuid        NOT NULL,
    instance_id          uuid,
    environment_id       uuid        NOT NULL,
    launcher_user_id     uuid,
    launcher_sa_id       uuid,
    launcher_instance_id uuid,
    principal_user_id    uuid,
    principal_sa_id      uuid,
    principal_source     text        NOT NULL CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run')),
    subject_issuer       text        CHECK (char_length(subject_issuer) BETWEEN 1 AND 512),
    subject_subject      text        CHECK (char_length(subject_subject) BETWEEN 1 AND 255),
    actor_chain          jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(actor_chain) = 'array'
                                                                  AND octet_length(actor_chain::text) <= 4096),
    parent_run_id        uuid,
    depth                smallint    NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 8),
    grant_id             uuid,
    task_ref             text        NOT NULL DEFAULT '' CHECK (char_length(task_ref) <= 256),
    state                text        NOT NULL DEFAULT 'ACTIVE'
                                     CHECK (state IN ('ACTIVE', 'ENDED', 'CANCELLED', 'EXPIRED', 'REVOKED')),
    end_reason           text        CHECK (char_length(end_reason) BETWEEN 1 AND 64),
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    ended_at             timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id),
    FOREIGN KEY (org_id, launcher_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, launcher_sa_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, launcher_instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, principal_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, principal_sa_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, parent_run_id) REFERENCES pc.runs (org_id, id),
    CONSTRAINT runs_one_launcher CHECK (num_nonnulls(launcher_user_id, launcher_sa_id, launcher_instance_id) = 1),
    CONSTRAINT runs_one_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id) = 1),
    -- HR-146: a subject token proves a user; a child run's launcher is the
    -- parent workload; otherwise the launcher represents itself.
    CONSTRAINT runs_principal_source CHECK (
        (principal_source = 'subject_token' AND principal_user_id IS NOT NULL
            AND subject_issuer IS NOT NULL AND subject_subject IS NOT NULL)
        OR (principal_source <> 'subject_token' AND subject_issuer IS NULL AND subject_subject IS NULL)),
    CONSTRAINT runs_child CHECK (
        (parent_run_id IS NULL AND depth = 0 AND principal_source <> 'parent_run' AND launcher_instance_id IS NULL)
        OR (parent_run_id IS NOT NULL AND depth > 0 AND principal_source = 'parent_run'
            AND launcher_instance_id IS NOT NULL)),
    CONSTRAINT runs_self_launched CHECK (principal_source <> 'launcher'
        OR (principal_user_id IS NOT DISTINCT FROM launcher_user_id AND principal_sa_id IS NOT DISTINCT FROM launcher_sa_id)),
    CONSTRAINT runs_lifetime CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    CONSTRAINT runs_ended CHECK ((state = 'ACTIVE') = (ended_at IS NULL) AND (state = 'ACTIVE') = (end_reason IS NULL))
);
CREATE INDEX runs_agent ON pc.runs (org_id, agent_id, created_at);
CREATE INDEX runs_children ON pc.runs (org_id, parent_run_id) WHERE parent_run_id IS NOT NULL;
CREATE INDEX runs_active_expiry ON pc.runs (org_id, expires_at) WHERE state = 'ACTIVE';

ALTER TABLE pc.runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.runs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.runs TO pc_app;
GRANT UPDATE (instance_id, state, end_reason, ended_at) ON pc.runs TO pc_app;
GRANT SELECT ON pc.runs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.runs;
