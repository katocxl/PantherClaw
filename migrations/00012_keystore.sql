-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Keystore (SB-3, ADR-0012). Signing keys (Ed25519, one active per purpose)
-- and data encryption keys (one active per org and purpose). Private
-- material is stored only wrapped by a KEK from the KeyProvider, with AAD
-- binding org, purpose and key id/version (HR-062). pc_app may change only
-- the state columns, never key material.

-- +goose Up
CREATE TABLE pc.keys (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    kid                 text        NOT NULL CHECK (char_length(kid) BETWEEN 1 AND 128),
    purpose             text        NOT NULL CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints')),
    algorithm           text        NOT NULL DEFAULT 'EdDSA' CHECK (algorithm = 'EdDSA'),
    public_key          bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    wrapped_private_key bytea       NOT NULL CHECK (octet_length(wrapped_private_key) BETWEEN 32 AND 1024),
    kek_id              text        NOT NULL CHECK (char_length(kek_id) BETWEEN 1 AND 64),
    state               text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRING', 'REVOKED')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    state_changed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, kid)
);
CREATE UNIQUE INDEX keys_one_active_per_purpose ON pc.keys (org_id, purpose) WHERE state = 'ACTIVE';

CREATE TABLE pc.deks (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    purpose     text        NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,62}$'),
    version     integer     NOT NULL CHECK (version > 0),
    wrapped_key bytea       NOT NULL CHECK (octet_length(wrapped_key) BETWEEN 32 AND 1024),
    kek_id      text        NOT NULL CHECK (char_length(kek_id) BETWEEN 1 AND 64),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, purpose, version)
);
CREATE UNIQUE INDEX deks_one_active_per_purpose ON pc.deks (org_id, purpose) WHERE state = 'ACTIVE';

ALTER TABLE pc.keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.keys
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

ALTER TABLE pc.deks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.deks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.deks
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.keys, pc.deks TO pc_app;
GRANT UPDATE (state, state_changed_at) ON pc.keys TO pc_app;
GRANT UPDATE (state) ON pc.deks TO pc_app;

-- +goose Down
DROP TABLE pc.deks;
DROP TABLE pc.keys;
