-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Service and CLI authentication (SB-2, ADR-0016): service-account public
-- keys with a pinned algorithm (HR-095), pck_ API keys, device-flow codes,
-- CLI sessions (rotating refresh tokens bound to a device key) and the
-- client-assertion replay store. Secrets are stored only as SHA-256 hashes;
-- the PKCE verifier and nonce live on a device code only until its OIDC
-- callback completes. Expired rows are deleted by the authn janitor.

-- +goose Up
CREATE TABLE pc.service_account_keys (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    service_account_id uuid        NOT NULL,
    kid                text        NOT NULL CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    alg                text        NOT NULL CHECK (alg IN ('EdDSA', 'ES256')),
    public_jwk         bytea       NOT NULL CHECK (octet_length(public_jwk) BETWEEN 2 AND 4096),
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, service_account_id, kid),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id)
);

CREATE TABLE pc.api_keys (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    service_account_id uuid        NOT NULL,
    name               text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    secret_hash        bytea       NOT NULL CHECK (octet_length(secret_hash) = 32),
    hint               text        NOT NULL CHECK (char_length(hint) BETWEEN 1 AND 16),
    scopes             text[]      NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 64),
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    last_used_at       timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, secret_hash),
    UNIQUE (org_id, service_account_id, name),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id)
);

-- Device flow (RFC 8628 shape). PENDING → AUTHORIZING (browser confirmed,
-- sent to the IdP) → APPROVED (OIDC callback succeeded) → CONSUMED (CLI got
-- its tokens); DENIED from any open state.
CREATE TABLE pc.device_codes (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    code_hash        bytea       NOT NULL CHECK (octet_length(code_hash) = 32),
    user_code        text        NOT NULL CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'),
    device_jkt       text        NOT NULL CHECK (device_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    device_jwk       bytea       NOT NULL CHECK (octet_length(device_jwk) BETWEEN 2 AND 4096),
    device_name      text        NOT NULL DEFAULT '' CHECK (char_length(device_name) <= 64),
    requested_ip     text        NOT NULL DEFAULT '' CHECK (char_length(requested_ip) <= 64),
    invitation_id    uuid,
    provider         text        CHECK (provider IS NULL OR provider ~ '^[a-z0-9-]{1,32}$'),
    state            text        NOT NULL DEFAULT 'PENDING'
                                 CHECK (state IN ('PENDING', 'AUTHORIZING', 'APPROVED', 'DENIED', 'CONSUMED')),
    oauth_state_hash bytea       CHECK (oauth_state_hash IS NULL OR octet_length(oauth_state_hash) = 32),
    binding_hash     bytea       CHECK (binding_hash IS NULL OR octet_length(binding_hash) = 32),
    nonce            text        CHECK (nonce IS NULL OR char_length(nonce) <= 64),
    pkce_verifier    text        CHECK (pkce_verifier IS NULL OR char_length(pkce_verifier) <= 128),
    attempts         integer     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    user_id          uuid,
    deny_reason      text        CHECK (deny_reason IS NULL OR char_length(deny_reason) <= 64),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    last_polled_at   timestamptz,
    approved_at      timestamptz,
    consumed_at      timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, code_hash),
    UNIQUE (org_id, oauth_state_hash),
    FOREIGN KEY (org_id, invitation_id) REFERENCES pc.invitations (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);
CREATE UNIQUE INDEX device_codes_open_user_code ON pc.device_codes (org_id, user_code)
    WHERE state IN ('PENDING', 'AUTHORIZING');

-- One CLI login. The refresh token rotates on every use; the previous hash is
-- kept so that reuse of a rotated token revokes the session.
CREATE TABLE pc.cli_sessions (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    user_id           uuid        NOT NULL,
    device_jkt        text        NOT NULL CHECK (device_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    device_jwk        bytea       NOT NULL CHECK (octet_length(device_jwk) BETWEEN 2 AND 4096),
    device_name       text        NOT NULL DEFAULT '' CHECK (char_length(device_name) <= 64),
    refresh_hash      bytea       NOT NULL CHECK (octet_length(refresh_hash) = 32),
    prev_refresh_hash bytea       CHECK (prev_refresh_hash IS NULL OR octet_length(prev_refresh_hash) = 32),
    generation        integer     NOT NULL DEFAULT 1 CHECK (generation >= 1),
    state             text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    revoke_reason     text        CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 64),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    refreshed_at      timestamptz,
    revoked_at        timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, refresh_hash),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX cli_sessions_prev_refresh ON pc.cli_sessions (org_id, prev_refresh_hash)
    WHERE prev_refresh_hash IS NOT NULL;
CREATE INDEX cli_sessions_user ON pc.cli_sessions (org_id, user_id) WHERE state = 'ACTIVE';

-- Client-assertion jtis, recorded only after the assertion's signature
-- verified (HR-090 ordering). issuer is "sa:<id>" or "device:<jkt>".
CREATE TABLE pc.auth_replay (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    issuer     text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 100),
    jti        text        NOT NULL CHECK (char_length(jti) BETWEEN 1 AND 128),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, issuer, jti)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['service_account_keys', 'api_keys', 'device_codes', 'cli_sessions', 'auth_replay']
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

GRANT SELECT, INSERT ON pc.service_account_keys, pc.api_keys, pc.device_codes, pc.cli_sessions, pc.auth_replay TO pc_app;
GRANT UPDATE (state, revoked_at) ON pc.service_account_keys TO pc_app;
GRANT UPDATE (state, revoked_at, last_used_at) ON pc.api_keys TO pc_app;
GRANT UPDATE (provider, state, oauth_state_hash, binding_hash, nonce, pkce_verifier, attempts, user_id,
    deny_reason, last_polled_at, approved_at, consumed_at) ON pc.device_codes TO pc_app;
GRANT UPDATE (refresh_hash, prev_refresh_hash, generation, state, revoke_reason, refreshed_at, revoked_at)
    ON pc.cli_sessions TO pc_app;
GRANT DELETE ON pc.device_codes, pc.cli_sessions, pc.auth_replay TO pc_app;
GRANT SELECT (org_id, id, service_account_id, kid, alg, public_jwk, state, created_by, created_at, expires_at, revoked_at)
    ON pc.service_account_keys TO pc_audit_ro;
GRANT SELECT (org_id, id, service_account_id, name, hint, scopes, state, created_by, created_at, expires_at,
    revoked_at, last_used_at) ON pc.api_keys TO pc_audit_ro;
GRANT SELECT (org_id, id, user_id, device_jkt, device_name, generation, state, revoke_reason, created_at,
    expires_at, refreshed_at, revoked_at) ON pc.cli_sessions TO pc_audit_ro;

-- Access tokens are signed by their own key purpose (ADR-0016).
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens')) NOT VALID;
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;

-- +goose Down
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints')) NOT VALID;
DROP TABLE pc.auth_replay;
DROP TABLE pc.cli_sessions;
DROP TABLE pc.device_codes;
DROP TABLE pc.api_keys;
DROP TABLE pc.service_account_keys;
