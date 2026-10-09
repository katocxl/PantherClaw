-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Kill switch, modes and execution facts (G0 M6, HR-002, HR-010, HR-113,
-- HR-184, HR-186). org_containment records who engaged the kill switch, when
-- and why; a restore is a proposal by one person that a second person, with a
-- different WebAuthn credential, confirms within 30 minutes. Every change to
-- an org's epoch or kill switch notifies the containment watchers (payload:
-- the org id only, HR-056), whichever use case made it. Transactions and
-- permits record the connection and the route mode (monitor actions reserve
-- nothing); execution attempts record the access mode and the cooperative
-- outcome delegated.

-- +goose Up
ALTER TABLE pc.org_containment
    ADD COLUMN engaged_by    text        CHECK (engaged_by IS NULL OR char_length(engaged_by) BETWEEN 1 AND 100),
    ADD COLUMN engaged_at    timestamptz,
    ADD COLUMN engage_reason text        CHECK (engage_reason IS NULL OR char_length(engage_reason) <= 500),
    ADD CONSTRAINT org_containment_engaged CHECK (kill_switch = (engaged_at IS NOT NULL) AND
                                                  (engaged_at IS NULL) = (engaged_by IS NULL)) NOT VALID;
ALTER TABLE pc.org_containment VALIDATE CONSTRAINT org_containment_engaged;

-- +goose StatementBegin
CREATE FUNCTION pc.notify_containment_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('pc_containment', NEW.org_id::text);
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER org_containment_notify AFTER UPDATE OF epoch, kill_switch ON pc.org_containment
    FOR EACH ROW EXECUTE FUNCTION pc.notify_containment_change();

-- A proposal to restore after the kill switch (HR-113): two distinct people
-- with two distinct WebAuthn credentials. At most one PENDING per org.
CREATE TABLE pc.kill_switch_requests (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    epoch              bigint      NOT NULL CHECK (epoch > 0),
    proposed_by        uuid        NOT NULL,
    proposer_cred      uuid        NOT NULL,
    reason             text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    state              text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'CONFIRMED', 'EXPIRED', 'CANCELLED')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    decided_by         uuid,
    decider_cred       uuid,
    decided_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, proposed_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, decided_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, proposer_cred) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, decider_cred) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 minutes'),
    CHECK ((state = 'PENDING') = (decided_at IS NULL)),
    CHECK (state <> 'CONFIRMED' OR (decided_by IS NOT NULL AND decider_cred IS NOT NULL)),
    CHECK (decided_by IS NULL OR state <> 'CONFIRMED' OR decided_by <> proposed_by),
    CHECK (decider_cred IS NULL OR decider_cred <> proposer_cred)
);
CREATE UNIQUE INDEX kill_switch_requests_pending ON pc.kill_switch_requests (org_id) WHERE state = 'PENDING';

ALTER TABLE pc.kill_switch_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.kill_switch_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.kill_switch_requests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

ALTER TABLE pc.transactions
    ADD COLUMN mode          text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce', 'monitor')),
    ADD COLUMN connection_id uuid,
    ADD CONSTRAINT transactions_connection_fk FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id);
ALTER TABLE pc.permits
    ADD COLUMN mode          text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce', 'monitor')),
    ADD COLUMN connection_id uuid,
    ADD CONSTRAINT permits_connection_fk FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id);

ALTER TABLE pc.execution_attempts DROP CONSTRAINT execution_attempts_outcome_check;
ALTER TABLE pc.execution_attempts ADD CONSTRAINT execution_attempts_outcome_check
    CHECK (outcome IN ('accepted', 'failed', 'unknown', 'delegated')) NOT VALID;
ALTER TABLE pc.execution_attempts VALIDATE CONSTRAINT execution_attempts_outcome_check;
ALTER TABLE pc.execution_attempts
    ADD COLUMN access_mode text CHECK (access_mode IS NULL OR
                                       access_mode IN ('pantherclaw_held', 'agent_held', 'target_enforced', 'none'));

GRANT SELECT, INSERT ON pc.kill_switch_requests TO pc_app;
GRANT UPDATE (state, decided_by, decider_cred, decided_at) ON pc.kill_switch_requests TO pc_app;
GRANT UPDATE (engaged_by, engaged_at, engage_reason) ON pc.org_containment TO pc_app;
GRANT SELECT ON pc.kill_switch_requests TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.execution_attempts DROP COLUMN access_mode;
ALTER TABLE pc.execution_attempts DROP CONSTRAINT execution_attempts_outcome_check;
ALTER TABLE pc.execution_attempts ADD CONSTRAINT execution_attempts_outcome_check
    CHECK (outcome IN ('accepted', 'failed', 'unknown')) NOT VALID;
ALTER TABLE pc.permits DROP CONSTRAINT permits_connection_fk, DROP COLUMN connection_id, DROP COLUMN mode;
ALTER TABLE pc.transactions DROP CONSTRAINT transactions_connection_fk, DROP COLUMN connection_id, DROP COLUMN mode;
DROP TABLE pc.kill_switch_requests;
DROP TRIGGER org_containment_notify ON pc.org_containment;
DROP FUNCTION pc.notify_containment_change();
REVOKE UPDATE (engaged_by, engaged_at, engage_reason) ON pc.org_containment FROM pc_app;
ALTER TABLE pc.org_containment DROP CONSTRAINT org_containment_engaged,
    DROP COLUMN engage_reason, DROP COLUMN engaged_at, DROP COLUMN engaged_by;
