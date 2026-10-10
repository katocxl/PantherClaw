-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approvals (G0 M5 part 2, HR-030..037, HR-039, HR-170..176). An approval
-- request is created only by the finalization that records a hold; its
-- binding (PAP-1 §8) is fixed then, together with the exact canonical input
-- it hashes, the requirements and the rendered display. pc_app may change
-- only its state columns: a changed binding supersedes the request, never
-- updates it (HR-171). A transaction has at most one live request, and an
-- agent at most one live restoration. Responses are inserted once and only
-- voided later; an approval or step-up keeps its WebAuthn assertion for M6
-- (HR-038). Evidence is untrusted and insert-only. Hold slots count pending
-- holds per grant and per run, changed by conditional updates (HR-037).
-- BINDING ceremonies sign the binding itself, so they are unique per
-- request (or batch) and user instead of per challenge (design decision 12).
-- Every new or changed request notifies the waiters of its transaction on
-- pc_wait with "org_id:transaction_id" only (HR-056, HR-174).

-- +goose Up
CREATE TABLE pc.approval_requests (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    subject_kind         text        NOT NULL CHECK (subject_kind IN ('ACTION', 'RESTORATION')),
    agent_id             uuid        NOT NULL,
    -- ACTION: the held transaction, the evaluation that recorded the hold,
    -- the run and its grant revision, and the variant key (SHA-256 of grant,
    -- operation and target).
    transaction_id       uuid,
    evaluation           integer     CHECK (evaluation BETWEEN 1 AND 64),
    run_id               uuid,
    grant_id             uuid,
    grant_revision       integer     CHECK (grant_revision > 0),
    variant_key          bytea       CHECK (octet_length(variant_key) = 32),
    -- RESTORATION: the person who asked; they never decide it (decision 11).
    requested_by         uuid,
    operation            text        NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 128),
    previous_id          uuid,
    binding              bytea       NOT NULL CHECK (octet_length(binding) = 32),
    binding_input        bytea       NOT NULL CHECK (octet_length(binding_input) BETWEEN 2 AND 16384),
    requirements         jsonb       NOT NULL CHECK (jsonb_typeof(requirements) = 'array'
                                                     AND jsonb_array_length(requirements) BETWEEN 1 AND 16
                                                     AND octet_length(requirements::text) <= 16384),
    display              jsonb       NOT NULL CHECK (jsonb_typeof(display) = 'object'
                                                     AND octet_length(display::text) <= 65536),
    display_hash         bytea       NOT NULL CHECK (octet_length(display_hash) = 32),
    state                text        NOT NULL DEFAULT 'PENDING'
                                     CHECK (state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED', 'CONSUMED',
                                                      'DECLINED', 'EXPIRED', 'INVALIDATED', 'SUPERSEDED')),
    end_reason           text        CHECK (end_reason ~ '^[A-Z][A-Z_]{1,63}$'),
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- The binding covers the deadline in whole seconds (PAP-1 §8).
    deadline_at          timestamptz NOT NULL CHECK (deadline_at = date_trunc('second', deadline_at)),
    evidence_deadline_at timestamptz,
    approved_at          timestamptz,
    consume_by           timestamptz,
    consumed_at          timestamptz,
    permit_id            uuid,
    ended_at             timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, binding),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, previous_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, permit_id) REFERENCES pc.permits (org_id, id),
    CONSTRAINT approval_requests_subject CHECK (
        (subject_kind = 'ACTION' AND transaction_id IS NOT NULL AND evaluation IS NOT NULL AND run_id IS NOT NULL
            AND grant_id IS NOT NULL AND grant_revision IS NOT NULL AND variant_key IS NOT NULL AND requested_by IS NULL)
        OR (subject_kind = 'RESTORATION' AND transaction_id IS NULL AND evaluation IS NULL AND run_id IS NULL
            AND grant_id IS NULL AND grant_revision IS NULL AND variant_key IS NULL AND requested_by IS NOT NULL)),
    CONSTRAINT approval_requests_deadline CHECK (deadline_at > created_at AND deadline_at <= created_at + interval '7 days'),
    CONSTRAINT approval_requests_evidence CHECK (
        (state <> 'EVIDENCE_REQUESTED' OR evidence_deadline_at IS NOT NULL)
        AND (evidence_deadline_at IS NULL OR evidence_deadline_at < deadline_at)),
    CONSTRAINT approval_requests_approved CHECK (
        (approved_at IS NULL) = (consume_by IS NULL)
        AND (state NOT IN ('APPROVED', 'CONSUMED') OR approved_at IS NOT NULL)
        AND (consume_by IS NULL OR (consume_by > approved_at AND consume_by <= deadline_at))),
    CONSTRAINT approval_requests_consumed CHECK (
        (state = 'CONSUMED') = (consumed_at IS NOT NULL)
        AND (permit_id IS NULL OR state = 'CONSUMED')
        AND (state <> 'CONSUMED' OR subject_kind = 'RESTORATION' OR permit_id IS NOT NULL)),
    CONSTRAINT approval_requests_ended CHECK (
        (state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')) = (ended_at IS NULL)
        AND (state IN ('DECLINED', 'EXPIRED', 'INVALIDATED', 'SUPERSEDED')) = (end_reason IS NOT NULL))
);
-- One live request per transaction, one live restoration per agent.
CREATE UNIQUE INDEX approval_requests_live_transaction ON pc.approval_requests (org_id, transaction_id)
    WHERE transaction_id IS NOT NULL AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');
CREATE UNIQUE INDEX approval_requests_live_restoration ON pc.approval_requests (org_id, agent_id)
    WHERE subject_kind = 'RESTORATION' AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');
CREATE INDEX approval_requests_transaction ON pc.approval_requests (org_id, transaction_id, created_at)
    WHERE transaction_id IS NOT NULL;
CREATE INDEX approval_requests_variant ON pc.approval_requests (org_id, variant_key, created_at)
    WHERE variant_key IS NOT NULL;
CREATE INDEX approval_requests_open ON pc.approval_requests (org_id, deadline_at)
    WHERE state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- A decision taken on several ACTION_HOLD requests at once (HR-175, Team).
-- An APPROVE batch is created when its ceremony starts and completed when
-- the assertion over its batch hash verifies; a DECLINE batch is complete
-- when it is inserted. Each request still gets its own response.
CREATE TABLE pc.approval_batches (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('APPROVE', 'DECLINE')),
    user_id        uuid        NOT NULL,
    session_id     uuid,
    cli_session_id uuid,
    batch_hash     bytea       NOT NULL CHECK (octet_length(batch_hash) = 32),
    request_ids    uuid[]      NOT NULL CHECK (cardinality(request_ids) BETWEEN 1 AND 25),
    state          text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'COMPLETED')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sessions (org_id, id),
    FOREIGN KEY (org_id, cli_session_id) REFERENCES pc.cli_sessions (org_id, id),
    CONSTRAINT approval_batches_session CHECK (num_nonnulls(session_id, cli_session_id) = 1
                                               AND (kind = 'DECLINE' OR session_id IS NOT NULL)),
    CONSTRAINT approval_batches_completed CHECK ((state = 'COMPLETED') = (completed_at IS NOT NULL))
);

-- One decider's response. Approvals and step-ups come only from a browser
-- session with a WebAuthn assertion (decision 1) and count toward exactly
-- one requirement of the request; declines, evidence requests and narrower
-- proposals grant nothing and may come from a CLI session too (HR-172).
CREATE TABLE pc.approval_responses (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    request_id         uuid        NOT NULL,
    user_id            uuid        NOT NULL,
    session_id         uuid,
    cli_session_id     uuid,
    kind               text        NOT NULL CHECK (kind IN ('APPROVE', 'STEP_UP', 'DECLINE', 'REQUEST_EVIDENCE',
                                                            'PROPOSE_NARROWER')),
    requirement        smallint    CHECK (requirement BETWEEN 0 AND 15),
    credential_id      uuid,
    authenticator_data bytea       CHECK (octet_length(authenticator_data) BETWEEN 37 AND 4096),
    client_data_json   bytea       CHECK (octet_length(client_data_json) BETWEEN 2 AND 4096),
    signature          bytea       CHECK (octet_length(signature) BETWEEN 1 AND 1024),
    reason_code        text        CHECK (reason_code ~ '^[A-Z][A-Z_]{1,63}$'),
    alternative_code   text        CHECK (alternative_code ~ '^[A-Z][A-Z_]{1,63}$'),
    note               text        NOT NULL DEFAULT '' CHECK (char_length(note) <= 500),
    proposed_params    jsonb       CHECK (jsonb_typeof(proposed_params) = 'object'
                                          AND octet_length(proposed_params::text) <= 16384),
    batch_id           uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    voided_at          timestamptz,
    void_reason        text        CHECK (void_reason IN ('ROLE_REMOVED', 'USER_DISABLED', 'CREDENTIAL_REMOVED',
                                                          'CREDENTIAL_SUSPENDED', 'NOT_ELIGIBLE')),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sessions (org_id, id),
    FOREIGN KEY (org_id, cli_session_id) REFERENCES pc.cli_sessions (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, batch_id) REFERENCES pc.approval_batches (org_id, id),
    CONSTRAINT approval_responses_session CHECK (num_nonnulls(session_id, cli_session_id) = 1),
    CONSTRAINT approval_responses_assertion CHECK (CASE WHEN kind IN ('APPROVE', 'STEP_UP')
        THEN session_id IS NOT NULL AND requirement IS NOT NULL AND credential_id IS NOT NULL
            AND authenticator_data IS NOT NULL AND client_data_json IS NOT NULL AND signature IS NOT NULL
        ELSE requirement IS NULL AND credential_id IS NULL AND authenticator_data IS NULL
            AND client_data_json IS NULL AND signature IS NULL END),
    CONSTRAINT approval_responses_decline CHECK (kind <> 'DECLINE' OR reason_code IN
        ('NOT_NEEDED', 'TOO_RISKY', 'WRONG_TARGET', 'NEEDS_DIFFERENT_APPROACH', 'OTHER')),
    CONSTRAINT approval_responses_codes CHECK ((kind IN ('DECLINE', 'REQUEST_EVIDENCE')) = (reason_code IS NOT NULL)
                                               AND (alternative_code IS NULL OR kind = 'DECLINE')),
    CONSTRAINT approval_responses_proposal CHECK ((kind = 'PROPOSE_NARROWER') = (proposed_params IS NOT NULL)),
    CONSTRAINT approval_responses_batch CHECK (batch_id IS NULL OR kind IN ('APPROVE', 'DECLINE')),
    CONSTRAINT approval_responses_void CHECK ((voided_at IS NULL) = (void_reason IS NULL)
                                              AND (voided_at IS NULL OR kind IN ('APPROVE', 'STEP_UP')))
);
-- One person counts once and one credential counts once per request
-- (HR-035); a request ends by at most one decline or narrower proposal.
CREATE UNIQUE INDEX approval_responses_one_per_user ON pc.approval_responses (org_id, request_id, user_id)
    WHERE kind IN ('APPROVE', 'STEP_UP');
CREATE UNIQUE INDEX approval_responses_one_per_credential ON pc.approval_responses (org_id, request_id, credential_id)
    WHERE credential_id IS NOT NULL;
CREATE UNIQUE INDEX approval_responses_one_ending ON pc.approval_responses (org_id, request_id)
    WHERE kind IN ('DECLINE', 'PROPOSE_NARROWER');
CREATE INDEX approval_responses_user ON pc.approval_responses (org_id, user_id) WHERE voided_at IS NULL;

-- A void is final: a voided response never counts again (HR-170).
-- +goose StatementBegin
CREATE FUNCTION pc.approval_responses_void_once() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.voided_at IS NOT NULL THEN
        RAISE EXCEPTION 'approval response % is already void', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER approval_responses_void_once BEFORE UPDATE ON pc.approval_responses
    FOR EACH ROW EXECUTE FUNCTION pc.approval_responses_void_once();

-- Untrusted notes from the run's workload or its launcher or principal
-- (HR-172): at most 4 KiB each; the application allows 20 per request.
CREATE TABLE pc.approval_evidence (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    request_id         uuid        NOT NULL,
    author_kind        text        NOT NULL CHECK (author_kind IN ('workload', 'user')),
    author_user_id     uuid,
    author_instance_id uuid,
    note               text        NOT NULL CHECK (octet_length(note) BETWEEN 1 AND 4096),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.approval_requests (org_id, id),
    FOREIGN KEY (org_id, author_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, author_instance_id) REFERENCES pc.agent_instances (org_id, id),
    CONSTRAINT approval_evidence_author CHECK (
        (author_kind = 'user' AND author_user_id IS NOT NULL AND author_instance_id IS NULL)
        OR (author_kind = 'workload' AND author_instance_id IS NOT NULL AND author_user_id IS NULL))
);
CREATE INDEX approval_evidence_request ON pc.approval_evidence (org_id, request_id, created_at);

-- Pending holds (PENDING, EVIDENCE_REQUESTED, or APPROVED and not yet used)
-- per grant and per run (HR-037, decision 7). The finalization takes a slot
-- with a conditional update below the cap; leaving a pending state gives it
-- back in the same transaction.
CREATE TABLE pc.hold_slots (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    scope_kind text        NOT NULL CHECK (scope_kind IN ('grant', 'run')),
    scope_id   uuid        NOT NULL,
    pending    integer     NOT NULL DEFAULT 0 CHECK (pending BETWEEN 0 AND 100),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, scope_kind, scope_id)
);

-- The approval binding ceremony (HR-033): its challenge is the binding (or
-- the batch hash) itself.
ALTER TABLE pc.webauthn_ceremonies
    ADD COLUMN approval_request_id uuid,
    ADD COLUMN batch_id            uuid,
    DROP CONSTRAINT webauthn_ceremonies_purpose_check,
    DROP CONSTRAINT webauthn_ceremonies_org_id_challenge_key,
    ADD CONSTRAINT webauthn_ceremonies_purpose_check CHECK (purpose IN ('REGISTRATION', 'STEP_UP', 'BINDING')) NOT VALID,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id) <= 1) NOT VALID,
    ADD CONSTRAINT webauthn_ceremonies_request_fk FOREIGN KEY (org_id, approval_request_id)
        REFERENCES pc.approval_requests (org_id, id),
    ADD CONSTRAINT webauthn_ceremonies_batch_fk FOREIGN KEY (org_id, batch_id)
        REFERENCES pc.approval_batches (org_id, id);
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_purpose_check;
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
CREATE UNIQUE INDEX webauthn_ceremonies_challenge ON pc.webauthn_ceremonies (org_id, challenge)
    WHERE purpose IN ('REGISTRATION', 'STEP_UP');
CREATE UNIQUE INDEX webauthn_ceremonies_binding_request ON pc.webauthn_ceremonies (org_id, approval_request_id, user_id)
    WHERE approval_request_id IS NOT NULL AND consumed_at IS NULL;
CREATE UNIQUE INDEX webauthn_ceremonies_binding_batch ON pc.webauthn_ceremonies (org_id, batch_id, user_id)
    WHERE batch_id IS NOT NULL AND consumed_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION pc.notify_wait() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.transaction_id IS NOT NULL THEN
        PERFORM pg_notify('pc_wait', NEW.org_id::text || ':' || NEW.transaction_id::text);
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER approval_requests_notify_wait AFTER INSERT OR UPDATE OF state ON pc.approval_requests
    FOR EACH ROW EXECUTE FUNCTION pc.notify_wait();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['approval_requests', 'approval_batches', 'approval_responses', 'approval_evidence', 'hold_slots']
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

GRANT SELECT, INSERT ON pc.approval_requests, pc.approval_batches, pc.approval_responses, pc.approval_evidence,
    pc.hold_slots TO pc_app;
GRANT UPDATE (state, end_reason, evidence_deadline_at, approved_at, consume_by, consumed_at, permit_id, ended_at)
    ON pc.approval_requests TO pc_app;
GRANT UPDATE (state, completed_at) ON pc.approval_batches TO pc_app;
GRANT UPDATE (voided_at, void_reason) ON pc.approval_responses TO pc_app;
GRANT UPDATE (pending, updated_at) ON pc.hold_slots TO pc_app;
GRANT SELECT ON pc.approval_requests, pc.approval_batches, pc.approval_responses, pc.approval_evidence, pc.hold_slots
    TO pc_audit_ro;

-- +goose Down
DROP TRIGGER approval_requests_notify_wait ON pc.approval_requests;
DROP FUNCTION pc.notify_wait();
DELETE FROM pc.webauthn_ceremonies WHERE purpose = 'BINDING';
DROP INDEX pc.webauthn_ceremonies_binding_batch;
DROP INDEX pc.webauthn_ceremonies_binding_request;
DROP INDEX pc.webauthn_ceremonies_challenge;
ALTER TABLE pc.webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_batch_fk,
    DROP CONSTRAINT webauthn_ceremonies_request_fk,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    DROP CONSTRAINT webauthn_ceremonies_purpose_check,
    DROP COLUMN batch_id,
    DROP COLUMN approval_request_id,
    ADD CONSTRAINT webauthn_ceremonies_purpose_check CHECK (purpose IN ('REGISTRATION', 'STEP_UP')),
    ADD CONSTRAINT webauthn_ceremonies_org_id_challenge_key UNIQUE (org_id, challenge);
DROP TABLE pc.hold_slots;
DROP TABLE pc.approval_evidence;
DROP TRIGGER approval_responses_void_once ON pc.approval_responses;
DROP FUNCTION pc.approval_responses_void_once();
DROP TABLE pc.approval_responses;
DROP TABLE pc.approval_batches;
DROP TABLE pc.approval_requests;
