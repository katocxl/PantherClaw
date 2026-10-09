-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Gateways (G0 M6, HR-180..182): gateway records, single-use enrollment
-- tokens (stored as SHA-256), one row per certificate the internal CA issued,
-- and the X-Wing broker keys a gateway registered over its own mTLS identity.
-- The certificate row is what the gateway listener checks on every call
-- (HR-181), so revoking a row revokes the certificate at once. A gateway's
-- config_version moves whenever something it serves changes; the trigger
-- tells the containment watchers (payload: the org id only, HR-056).

-- +goose Up
CREATE TABLE pc.gateways (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    name           text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    state          text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    config_version bigint      NOT NULL DEFAULT 1 CHECK (config_version > 0),
    created_by     text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at     timestamptz NOT NULL DEFAULT now(),
    revoked_by     text        CHECK (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 100),
    revoked_at     timestamptz,
    revoke_reason  text        CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 500),
    PRIMARY KEY (org_id, id),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- A revoked gateway frees its name.
CREATE UNIQUE INDEX gateways_name ON pc.gateways (org_id, name) WHERE state = 'ACTIVE';

CREATE TABLE pc.gateway_enrollment_tokens (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    gateway_id   uuid        NOT NULL,
    token_hash   bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    used_cert_id uuid,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, token_hash),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    CHECK ((used_at IS NULL) = (used_cert_id IS NULL))
);
CREATE INDEX gateway_enrollment_tokens_gateway ON pc.gateway_enrollment_tokens (org_id, gateway_id);

-- One certificate the internal CA issued to a gateway. id is the cert id in
-- the certificate's URI SAN. SUPERSEDED (by a renewal) is accepted for 10
-- more minutes; REVOKED never again.
CREATE TABLE pc.gateway_certs (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    gateway_id     uuid        NOT NULL,
    serial         bytea       NOT NULL CHECK (octet_length(serial) BETWEEN 1 AND 20),
    key_thumbprint text        NOT NULL CHECK (key_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    issued_via     text        NOT NULL CHECK (issued_via IN ('ENROLL', 'RENEW')),
    previous_id    uuid,
    not_before     timestamptz NOT NULL,
    not_after      timestamptz NOT NULL,
    state          text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
    issued_at      timestamptz NOT NULL DEFAULT now(),
    superseded_at  timestamptz,
    revoked_at     timestamptz,
    revoke_reason  text        CHECK (revoke_reason IS NULL OR revoke_reason ~ '^[a-z0-9_]{1,64}$'),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, serial),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, previous_id) REFERENCES pc.gateway_certs (org_id, id),
    CHECK (not_after > not_before AND not_after <= not_before + interval '25 hours'),
    CHECK ((issued_via = 'RENEW') = (previous_id IS NOT NULL)),
    CHECK ((state = 'SUPERSEDED') = (superseded_at IS NOT NULL)),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX gateway_certs_gateway ON pc.gateway_certs (org_id, gateway_id, issued_at DESC);

ALTER TABLE pc.gateway_enrollment_tokens ADD CONSTRAINT gateway_enrollment_tokens_cert_fk
    FOREIGN KEY (org_id, used_cert_id) REFERENCES pc.gateway_certs (org_id, id);

-- X-Wing public keys (1,216 bytes: ML-KEM-768 1,184 + X25519 32) that a
-- gateway registered over its own mTLS identity (HR-182). At most one ACTIVE
-- per gateway; registering the same key again is a no-op.
CREATE TABLE pc.broker_keys (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    gateway_id    uuid        NOT NULL,
    version       integer     NOT NULL CHECK (version > 0),
    public_key    bytea       NOT NULL CHECK (octet_length(public_key) = 1216),
    fingerprint   text        NOT NULL CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    cert_id       uuid        NOT NULL,
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRED')),
    registered_at timestamptz NOT NULL DEFAULT now(),
    retired_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, gateway_id, version),
    UNIQUE (org_id, gateway_id, fingerprint),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, cert_id) REFERENCES pc.gateway_certs (org_id, id),
    CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX broker_keys_active ON pc.broker_keys (org_id, gateway_id) WHERE state = 'ACTIVE';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['gateways', 'gateway_enrollment_tokens', 'gateway_certs', 'broker_keys']
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

-- A change to what a gateway serves (its config_version) or to its state
-- wakes the containment watchers of its org. The payload is the org id only.
-- +goose StatementBegin
CREATE FUNCTION pc.notify_gateway_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('pc_containment', NEW.org_id::text);
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER gateways_notify AFTER UPDATE OF config_version, state ON pc.gateways
    FOR EACH ROW EXECUTE FUNCTION pc.notify_gateway_change();

GRANT SELECT, INSERT ON pc.gateways, pc.gateway_enrollment_tokens, pc.gateway_certs, pc.broker_keys TO pc_app;
GRANT UPDATE (state, config_version, revoked_by, revoked_at, revoke_reason) ON pc.gateways TO pc_app;
GRANT UPDATE (used_at, used_cert_id) ON pc.gateway_enrollment_tokens TO pc_app;
GRANT UPDATE (state, superseded_at, revoked_at, revoke_reason) ON pc.gateway_certs TO pc_app;
GRANT UPDATE (state, retired_at) ON pc.broker_keys TO pc_app;
GRANT SELECT ON pc.gateways, pc.gateway_certs, pc.broker_keys TO pc_audit_ro;
GRANT SELECT (org_id, id, gateway_id, created_by, created_at, expires_at, used_at, used_cert_id)
    ON pc.gateway_enrollment_tokens TO pc_audit_ro;

-- The internal CA (gateway_ca) and action tokens (action_tokens) are new
-- signing-key purposes (G0 M6 formats).
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens')) NOT VALID;
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;

-- +goose Down
DELETE FROM pc.keys WHERE purpose IN ('gateway_ca', 'action_tokens');
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens')) NOT VALID;
DROP TRIGGER gateways_notify ON pc.gateways;
DROP FUNCTION pc.notify_gateway_change();
DROP TABLE pc.broker_keys;
ALTER TABLE pc.gateway_enrollment_tokens DROP CONSTRAINT gateway_enrollment_tokens_cert_fk;
DROP TABLE pc.gateway_certs;
DROP TABLE pc.gateway_enrollment_tokens;
DROP TABLE pc.gateways;
