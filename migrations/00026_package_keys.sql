-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Org package-signing keys (HR-162, ADR-0020; G0 M4 follow-up, Team
-- edition). One row per key an org registered: its public key (never the
-- private key), its state and, for anti-rollback (HR-123), the highest
-- targets metadata accepted under it. A kid is unique per org for good, so
-- a revoked key can never be registered again. pc_app may change only the
-- state, the revocation and the metadata columns, conditionally (HR-004);
-- the key itself never changes. package_versions records the key that
-- signed each version (NULL: a package root).

-- +goose Up
CREATE TABLE pc.package_signing_keys (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    kid                 text        NOT NULL CHECK (kid ~ '^org-packages-[A-Za-z0-9_-]{22}$'),
    public_key          bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    name                text        NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$'),
    state               text        NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED')),
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoke_reason       text        CHECK (revoke_reason IN ('ROTATED', 'COMPROMISED')),
    revoked_by          text        CHECK (char_length(revoked_by) BETWEEN 1 AND 100),
    revoked_at          timestamptz,
    metadata_version    bigint      CHECK (metadata_version > 0),
    metadata_digest     text        CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    metadata_expires_at timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, kid),
    CONSTRAINT package_signing_keys_revocation CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)
        AND (revoked_at IS NULL) = (revoke_reason IS NULL) AND (revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT package_signing_keys_metadata CHECK ((metadata_version IS NULL) = (metadata_digest IS NULL)
        AND (metadata_version IS NULL) = (metadata_expires_at IS NULL))
);

ALTER TABLE pc.package_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.package_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.package_signing_keys
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

ALTER TABLE pc.package_versions ADD COLUMN signing_key_id uuid;
ALTER TABLE pc.package_versions ADD CONSTRAINT package_versions_signing_key_fk
    FOREIGN KEY (org_id, signing_key_id) REFERENCES pc.package_signing_keys (org_id, id);

GRANT SELECT, INSERT ON pc.package_signing_keys TO pc_app;
GRANT UPDATE (state, revoke_reason, revoked_by, revoked_at, metadata_version, metadata_digest, metadata_expires_at)
    ON pc.package_signing_keys TO pc_app;
GRANT SELECT ON pc.package_signing_keys TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.package_versions DROP CONSTRAINT package_versions_signing_key_fk;
ALTER TABLE pc.package_versions DROP COLUMN signing_key_id;
DROP TABLE pc.package_signing_keys;
