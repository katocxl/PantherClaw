-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Tool packages per org (G0 M4 part 2, design decision 20): the trusted
-- targets-metadata state (anti-rollback, HR-123), packages, their versions
-- with the exact signed bytes and lifecycle state (F394), the per-org pin
-- (forward only, HR-123), the definitions by digest (what ActionIR pins)
-- and the consequence rules. Trust state is per org, so no table is
-- global and writable by pc_app. Signed bytes and definitions never
-- change: pc_app may update only lifecycle states and pins, conditionally
-- (HR-004).

-- +goose Up
CREATE TABLE pc.package_trust (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    version        bigint      NOT NULL CHECK (version > 0),
    payload_digest text        NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    expires_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

CREATE TABLE pc.tool_packages (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    name       text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,127}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TABLE pc.package_versions (
    org_id      uuid        NOT NULL,
    id          uuid        NOT NULL,
    package_id  uuid        NOT NULL,
    version     text        NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$'),
    file_digest text        NOT NULL CHECK (file_digest ~ '^sha256:[0-9a-f]{64}$'),
    raw         bytea       NOT NULL CHECK (octet_length(raw) BETWEEN 1 AND 1048576),
    state       text        NOT NULL CHECK (state IN ('UNCLASSIFIED', 'DRAFT', 'REVIEWED', 'ACTIVE', 'STALE',
                                                      'QUARANTINED', 'RETIRED')),
    imported_at timestamptz NOT NULL DEFAULT now(),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, package_id, version),
    FOREIGN KEY (org_id, package_id) REFERENCES pc.tool_packages (org_id, id)
);

CREATE TABLE pc.package_pins (
    org_id     uuid        NOT NULL,
    package_id uuid        NOT NULL,
    version_id uuid        NOT NULL,
    version    text        NOT NULL,
    digest     text        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, package_id),
    FOREIGN KEY (org_id, package_id) REFERENCES pc.tool_packages (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.package_versions (org_id, id)
);

CREATE TABLE pc.action_definitions (
    org_id     uuid  NOT NULL,
    id         uuid  NOT NULL,
    version_id uuid  NOT NULL,
    operation  text  NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    digest     text  NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    canonical  bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 262144),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, version_id, operation),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.package_versions (org_id, id)
);
CREATE INDEX action_definitions_digest ON pc.action_definitions (org_id, digest);

CREATE TABLE pc.consequence_rules (
    org_id     uuid  NOT NULL,
    id         uuid  NOT NULL,
    version_id uuid  NOT NULL,
    position   integer NOT NULL CHECK (position >= 0),
    canonical  bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 65536),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, version_id, position),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.package_versions (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['package_trust', 'tool_packages', 'package_versions', 'package_pins',
                             'action_definitions', 'consequence_rules']
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

GRANT SELECT, INSERT ON pc.package_trust, pc.tool_packages, pc.package_versions, pc.package_pins,
    pc.action_definitions, pc.consequence_rules TO pc_app;
GRANT UPDATE (version, payload_digest, expires_at, updated_at) ON pc.package_trust TO pc_app;
GRANT UPDATE (state, changed_at) ON pc.package_versions TO pc_app;
GRANT UPDATE (version_id, version, digest, updated_at) ON pc.package_pins TO pc_app;
GRANT SELECT ON pc.package_versions, pc.package_pins, pc.action_definitions TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.consequence_rules;
DROP TABLE pc.action_definitions;
DROP TABLE pc.package_pins;
DROP TABLE pc.package_versions;
DROP TABLE pc.tool_packages;
DROP TABLE pc.package_trust;
