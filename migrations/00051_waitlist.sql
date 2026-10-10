-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The Agent Waitlist (G0 M5 part 2, PN-004, HR-173, HR-175, HR-177).
-- waitlist_entries (M3) gains the other five kinds, priority, routing
-- health, escalation and assignment. An entry's kind, subject, priority and
-- deadline come from PantherClaw's records only, at most one entry per
-- subject is open, and every transition is a conditional update (HR-177).
-- Escalation chains are immutable revisions per org or team (at most five
-- steps); routes record, insert-only, who was notified at which step.
-- waitlist_settings holds one row per org: the batch ceilings, shortened
-- deadlines, lowered hold caps and lengthened approver cooldowns, each
-- within the bounds of G0 M5 part 2 decisions 5-7 and 9; NULL means the
-- default.

-- +goose Up
ALTER TABLE pc.waitlist_entries
    DROP CONSTRAINT waitlist_entries_kind_check,
    DROP CONSTRAINT waitlist_entries_subject_type_check,
    ALTER COLUMN agent_id DROP NOT NULL,
    ADD COLUMN priority          smallint    NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4),
    ADD COLUMN run_id            uuid,
    ADD COLUMN transaction_id    uuid,
    ADD COLUMN requested_by      text        CHECK (char_length(requested_by) BETWEEN 1 AND 100),
    ADD COLUMN routing_health    text        NOT NULL DEFAULT 'OK'
                                             CHECK (routing_health IN ('OK', 'NO_ELIGIBLE_DECIDER', 'DELIVERY_FAILING')),
    ADD COLUMN escalation_step   smallint    NOT NULL DEFAULT 0 CHECK (escalation_step BETWEEN 0 AND 5),
    ADD COLUMN next_step_at      timestamptz,
    ADD COLUMN assignee_user_id  uuid,
    ADD COLUMN assigned_at       timestamptz,
    ADD COLUMN first_response_at timestamptz,
    ADD CONSTRAINT waitlist_entries_kind_check CHECK (kind IN ('ADMISSION', 'ACCESS_REQUEST', 'ACTION_HOLD', 'TOOL_REVIEW',
                                                               'RESTORATION', 'RECONCILIATION')) NOT VALID,
    ADD CONSTRAINT waitlist_entries_subject_type_check CHECK (subject_type IN ('agent', 'instance', 'approval_request',
                                                                               'grant', 'package_version', 'transaction')) NOT VALID,
    -- Each kind has its own subject; only a tool review has no agent.
    ADD CONSTRAINT waitlist_entries_kind_subject CHECK (CASE kind
        WHEN 'ADMISSION' THEN subject_type IN ('agent', 'instance') AND agent_id IS NOT NULL
        WHEN 'ACCESS_REQUEST' THEN subject_type = 'grant' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND requested_by IS NOT NULL
        WHEN 'ACTION_HOLD' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id IS NOT NULL
        WHEN 'TOOL_REVIEW' THEN subject_type = 'package_version' AND agent_id IS NULL AND run_id IS NULL
        WHEN 'RESTORATION' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND requested_by IS NOT NULL
        WHEN 'RECONCILIATION' THEN subject_type = 'transaction' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id = subject_id
    END) NOT VALID,
    ADD CONSTRAINT waitlist_entries_assigned CHECK ((assignee_user_id IS NULL) = (assigned_at IS NULL)) NOT VALID,
    ADD CONSTRAINT waitlist_entries_run_fk FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    ADD CONSTRAINT waitlist_entries_transaction_fk FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    ADD CONSTRAINT waitlist_entries_assignee_fk FOREIGN KEY (org_id, assignee_user_id) REFERENCES pc.users (org_id, id);
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_kind_check;
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_subject_type_check;
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_kind_subject;
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_assigned;
DROP INDEX pc.waitlist_entries_open;
CREATE INDEX waitlist_entries_open ON pc.waitlist_entries (org_id, priority, deadline_at) WHERE state = 'OPEN';
CREATE INDEX waitlist_entries_kind_open ON pc.waitlist_entries (org_id, kind, deadline_at) WHERE state = 'OPEN';
CREATE INDEX waitlist_entries_next_step ON pc.waitlist_entries (org_id, next_step_at)
    WHERE state = 'OPEN' AND next_step_at IS NOT NULL;
CREATE INDEX waitlist_entries_run ON pc.waitlist_entries (org_id, run_id, kind) WHERE run_id IS NOT NULL;
CREATE INDEX waitlist_entries_assignee ON pc.waitlist_entries (org_id, assignee_user_id)
    WHERE state = 'OPEN' AND assignee_user_id IS NOT NULL;
GRANT UPDATE (priority, routing_health, escalation_step, next_step_at, assignee_user_id, assigned_at, first_response_at)
    ON pc.waitlist_entries TO pc_app;

-- An escalation chain (decision 8): the org's (team_id NULL) or one team's.
-- Each change is a new revision; the highest revision is current.
CREATE TABLE pc.escalation_chains (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    team_id    uuid,
    revision   integer     NOT NULL CHECK (revision > 0),
    steps      jsonb       NOT NULL CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 5
                                           AND octet_length(steps::text) <= 4096),
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE NULLS NOT DISTINCT (org_id, team_id, revision),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id)
);

-- Who an entry was routed to, at which escalation step and when: a person
-- (an eligible decider, or an agent owner told without a vote) or a channel.
CREATE TABLE pc.waitlist_routes (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    entry_id   uuid        NOT NULL,
    step       smallint    NOT NULL CHECK (step BETWEEN 0 AND 5),
    kind       text        NOT NULL CHECK (kind IN ('decider', 'owner', 'admin', 'channel')),
    user_id    uuid,
    channel_id uuid,
    routed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, entry_id) REFERENCES pc.waitlist_entries (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, channel_id) REFERENCES pc.notification_channels (org_id, id),
    CONSTRAINT waitlist_routes_recipient CHECK ((kind = 'channel') = (channel_id IS NOT NULL)
                                                AND num_nonnulls(user_id, channel_id) = 1)
);
CREATE INDEX waitlist_routes_entry ON pc.waitlist_routes (org_id, entry_id, step);
CREATE INDEX waitlist_routes_user ON pc.waitlist_routes (org_id, user_id, routed_at) WHERE user_id IS NOT NULL;

-- One row per org. Deadlines may only be shortened, hold caps only lowered
-- (the grant cap up to the hard maximum of 100) and cooldowns only
-- lengthened; batch_ceilings maps a currency to a canonical decimal and is
-- empty, so batch approval is off, until an admin sets one (decision 9).
CREATE TABLE pc.waitlist_settings (
    org_id                    uuid        NOT NULL REFERENCES pc.orgs (id),
    batch_ceilings            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(batch_ceilings) = 'object'
                                                                       AND octet_length(batch_ceilings::text) <= 2048),
    hold_deadline_s           integer     CHECK (hold_deadline_s BETWEEN 300 AND 3600),
    consume_window_s          integer     CHECK (consume_window_s BETWEEN 60 AND 900),
    access_request_deadline_s integer     CHECK (access_request_deadline_s BETWEEN 3600 AND 604800),
    tool_review_deadline_s    integer     CHECK (tool_review_deadline_s BETWEEN 3600 AND 2592000),
    restoration_deadline_s    integer     CHECK (restoration_deadline_s BETWEEN 300 AND 86400),
    reconciliation_deadline_s integer     CHECK (reconciliation_deadline_s BETWEEN 3600 AND 259200),
    max_holds_per_grant       smallint    CHECK (max_holds_per_grant BETWEEN 1 AND 100),
    max_holds_per_run         smallint    CHECK (max_holds_per_run BETWEEN 1 AND 5),
    min_account_age_s         integer     CHECK (min_account_age_s BETWEEN 604800 AND 31536000),
    min_role_age_s            integer     CHECK (min_role_age_s BETWEEN 86400 AND 31536000),
    min_credential_age_s      integer     CHECK (min_credential_age_s BETWEEN 86400 AND 31536000),
    self_grant_delay_s        integer     CHECK (self_grant_delay_s BETWEEN 86400 AND 31536000),
    updated_by                text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['escalation_chains', 'waitlist_routes', 'waitlist_settings']
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

GRANT SELECT, INSERT ON pc.escalation_chains, pc.waitlist_routes, pc.waitlist_settings TO pc_app;
GRANT UPDATE (batch_ceilings, hold_deadline_s, consume_window_s, access_request_deadline_s, tool_review_deadline_s,
    restoration_deadline_s, reconciliation_deadline_s, max_holds_per_grant, max_holds_per_run, min_account_age_s,
    min_role_age_s, min_credential_age_s, self_grant_delay_s, updated_by, updated_at) ON pc.waitlist_settings TO pc_app;
GRANT SELECT ON pc.escalation_chains, pc.waitlist_routes, pc.waitlist_settings TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.waitlist_settings;
DROP TABLE pc.waitlist_routes;
DROP TABLE pc.escalation_chains;
DELETE FROM pc.waitlist_entries WHERE kind <> 'ADMISSION';
REVOKE UPDATE (priority, routing_health, escalation_step, next_step_at, assignee_user_id, assigned_at, first_response_at)
    ON pc.waitlist_entries FROM pc_app;
DROP INDEX pc.waitlist_entries_assignee;
DROP INDEX pc.waitlist_entries_run;
DROP INDEX pc.waitlist_entries_next_step;
DROP INDEX pc.waitlist_entries_kind_open;
DROP INDEX pc.waitlist_entries_open;
CREATE INDEX waitlist_entries_open ON pc.waitlist_entries (org_id, kind, deadline_at) WHERE state = 'OPEN';
ALTER TABLE pc.waitlist_entries
    DROP CONSTRAINT waitlist_entries_assignee_fk,
    DROP CONSTRAINT waitlist_entries_transaction_fk,
    DROP CONSTRAINT waitlist_entries_run_fk,
    DROP CONSTRAINT waitlist_entries_assigned,
    DROP CONSTRAINT waitlist_entries_kind_subject,
    DROP CONSTRAINT waitlist_entries_subject_type_check,
    DROP CONSTRAINT waitlist_entries_kind_check,
    DROP COLUMN first_response_at,
    DROP COLUMN assigned_at,
    DROP COLUMN assignee_user_id,
    DROP COLUMN next_step_at,
    DROP COLUMN escalation_step,
    DROP COLUMN routing_health,
    DROP COLUMN requested_by,
    DROP COLUMN transaction_id,
    DROP COLUMN run_id,
    DROP COLUMN priority,
    ALTER COLUMN agent_id SET NOT NULL,
    ADD CONSTRAINT waitlist_entries_kind_check CHECK (kind IN ('ADMISSION')),
    ADD CONSTRAINT waitlist_entries_subject_type_check CHECK (subject_type IN ('agent', 'instance'));
