-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Browser sign-in, browser sessions and WebAuthn (G0 M5 part 1, HR-150..156).
-- Secrets are stored only as SHA-256 hashes: the session cookie, its previous
-- value during the rotation grace, the sign-in state and its browser binding.
-- The nonce and PKCE verifier live on a login request only until its callback
-- consumes them. WebAuthn credentials keep public keys only, and a removed or
-- suspended credential keeps its row so that its id can never be registered
-- again in the org. Expired rows are deleted by the authn janitor.

-- +goose Up
-- One browser sign-in in progress: PENDING until the provider's callback
-- consumes it (single use, 10 minutes).
CREATE TABLE pc.login_requests (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    state_hash    bytea       CHECK (state_hash IS NULL OR octet_length(state_hash) = 32),
    binding_hash  bytea       CHECK (binding_hash IS NULL OR octet_length(binding_hash) = 32),
    nonce         text        CHECK (nonce IS NULL OR char_length(nonce) <= 64),
    pkce_verifier text        CHECK (pkce_verifier IS NULL OR char_length(pkce_verifier) <= 128),
    provider      text        NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    -- A PantherClaw path from a fixed list (HR-152): never another origin.
    next_path     text        NOT NULL CHECK (char_length(next_path) BETWEEN 2 AND 512 AND next_path ~ '^/[A-Za-z0-9]'),
    max_age       integer     CHECK (max_age IS NULL OR max_age BETWEEN 0 AND 3600),
    requested_ip  text        NOT NULL DEFAULT '' CHECK (char_length(requested_ip) <= 64),
    state         text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'CONSUMED')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, state_hash),
    CHECK ((state = 'PENDING') = (consumed_at IS NULL)),
    -- Pending: holds its state and binding. Consumed: holds no secret at all.
    CHECK (state <> 'PENDING' OR (state_hash IS NOT NULL AND binding_hash IS NOT NULL)),
    CHECK (state = 'PENDING' OR (state_hash IS NULL AND binding_hash IS NULL AND nonce IS NULL AND pkce_verifier IS NULL))
);

-- A security key or passkey of one user. state_reason says why a credential
-- is no longer ACTIVE; aaguid is untrusted (attestation "none").
CREATE TABLE pc.webauthn_credentials (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    credential_id   bytea       NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    public_key      bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 2048),
    alg             integer     NOT NULL CHECK (alg IN (-7, -8, -257)),
    sign_count      bigint      NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    backup_eligible boolean     NOT NULL,
    backup_state    boolean     NOT NULL,
    transports      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
    aaguid          uuid,
    attestation_fmt text        NOT NULL CHECK (attestation_fmt ~ '^[a-z0-9-]{1,32}$'),
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    state           text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
    state_reason    text        CHECK (state_reason IS NULL OR state_reason IN ('CLONE_SUSPECTED', 'USER_REMOVED', 'ADMIN_REMOVED')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    changed_at      timestamptz,
    changed_by      text        CHECK (changed_by IS NULL OR char_length(changed_by) BETWEEN 1 AND 100),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, credential_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'ACTIVE') = (state_reason IS NULL)),
    CHECK ((state = 'ACTIVE') = (changed_at IS NULL)),
    CHECK (state <> 'SUSPENDED' OR state_reason = 'CLONE_SUSPECTED'),
    CHECK (state <> 'REMOVED' OR state_reason IN ('USER_REMOVED', 'ADMIN_REMOVED'))
);
CREATE INDEX webauthn_credentials_user ON pc.webauthn_credentials (org_id, user_id);

-- One browser session (HR-150). The previous secret hash is kept for the
-- 60-second rotation grace; presenting it later ends the session. Idle (30
-- minutes from last_seen_at) and absolute (expires_at) expiry are checked by
-- the database clock on every request.
CREATE TABLE pc.sessions (
    org_id                uuid        NOT NULL REFERENCES pc.orgs (id),
    id                    uuid        NOT NULL,
    user_id               uuid        NOT NULL,
    secret_hash           bytea       NOT NULL CHECK (octet_length(secret_hash) = 32),
    prev_secret_hash      bytea       CHECK (prev_secret_hash IS NULL OR octet_length(prev_secret_hash) = 32),
    rotated_at            timestamptz,
    generation            integer     NOT NULL DEFAULT 1 CHECK (generation >= 1),
    provider              text        NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    -- The provider's auth_time when it sent one (always when max_age was
    -- requested); NULL means the provider did not say when the person signed in.
    auth_time             timestamptz,
    roles_digest          bytea       NOT NULL CHECK (octet_length(roles_digest) = 32),
    step_up_at            timestamptz,
    step_up_credential_id uuid,
    user_agent            text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    client_ip             text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    state                 text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ENDED')),
    end_reason            text        CHECK (end_reason IS NULL OR end_reason IN
                                         ('LOGOUT', 'REVOKED', 'ADMIN_REVOKED', 'IDLE', 'EXPIRED', 'REUSE', 'SESSION_LIMIT')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    ended_at              timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, secret_hash),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, step_up_credential_id) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((state = 'ENDED') = (end_reason IS NOT NULL AND ended_at IS NOT NULL)),
    CHECK ((step_up_at IS NULL) = (step_up_credential_id IS NULL)),
    CHECK ((prev_secret_hash IS NULL) = (rotated_at IS NULL)),
    CHECK (expires_at <= created_at + interval '12 hours')
);
CREATE INDEX sessions_prev_secret ON pc.sessions (org_id, prev_secret_hash) WHERE prev_secret_hash IS NOT NULL;
CREATE INDEX sessions_user_active ON pc.sessions (org_id, user_id) WHERE state = 'ACTIVE';

-- A pending WebAuthn ceremony (HR-153): bound to one browser session and
-- user, 5 minutes, consumed once by a conditional update. Part 2 widens the
-- purpose CHECK with the approval binding.
CREATE TABLE pc.webauthn_ceremonies (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    session_id          uuid        NOT NULL,
    user_id             uuid        NOT NULL,
    purpose             text        NOT NULL CHECK (purpose IN ('REGISTRATION', 'STEP_UP')),
    challenge           bytea       NOT NULL CHECK (octet_length(challenge) = 32),
    allowed_credentials bytea[]     NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_credentials) <= 64),
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    consumed_at         timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, challenge),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sessions (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CHECK (expires_at <= created_at + interval '5 minutes')
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['login_requests', 'webauthn_credentials', 'sessions', 'webauthn_ceremonies']
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

GRANT SELECT, INSERT ON pc.login_requests, pc.webauthn_credentials, pc.sessions, pc.webauthn_ceremonies TO pc_app;
GRANT UPDATE (state_hash, binding_hash, nonce, pkce_verifier, state, consumed_at) ON pc.login_requests TO pc_app;
GRANT UPDATE (sign_count, backup_state, name, state, state_reason, last_used_at, changed_at, changed_by)
    ON pc.webauthn_credentials TO pc_app;
GRANT UPDATE (secret_hash, prev_secret_hash, rotated_at, generation, roles_digest, step_up_at, step_up_credential_id,
    state, end_reason, last_seen_at, ended_at) ON pc.sessions TO pc_app;
GRANT UPDATE (consumed_at) ON pc.webauthn_ceremonies TO pc_app;
GRANT DELETE ON pc.login_requests, pc.sessions, pc.webauthn_ceremonies TO pc_app;
GRANT SELECT (org_id, id, user_id, provider, auth_time, step_up_at, step_up_credential_id, user_agent, client_ip, state,
    end_reason, created_at, last_seen_at, expires_at, ended_at, generation) ON pc.sessions TO pc_audit_ro;
GRANT SELECT (org_id, id, user_id, credential_id, alg, sign_count, backup_eligible, backup_state, transports, aaguid,
    attestation_fmt, name, state, state_reason, created_at, last_used_at, changed_at, changed_by)
    ON pc.webauthn_credentials TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.webauthn_ceremonies;
DROP TABLE pc.sessions;
DROP TABLE pc.webauthn_credentials;
DROP TABLE pc.login_requests;
