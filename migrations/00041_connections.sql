-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connections, routes, sealed credentials and circuit states (G0 M6,
-- HR-060, HR-061, HR-077, HR-078, HR-182..184). A connection is one target
-- served by one gateway through one tool package; each package route runs in
-- monitor or enforce mode (connection_routes overrides default_mode). A
-- credential is an HPKE (X-Wing) sealed blob that only the gateway holding
-- the broker key can open: the server never sees the plaintext, and
-- pc_audit_ro cannot read the sealed bytes. Quarantining, retiring and every
-- other strengthening change raise the containment epoch in the same
-- transaction (application code); the org_containment trigger then wakes the
-- gateways' containment streams.

-- +goose Up
CREATE TABLE pc.connections (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    name               text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    kind               text        NOT NULL CHECK (kind IN ('http', 'mcp', 'local')),
    gateway_id         uuid        NOT NULL,
    package            text        NOT NULL CHECK (package ~ '^[a-z0-9][a-z0-9.-]{0,127}$'),
    base_url           text        CHECK (base_url IS NULL OR (char_length(base_url) BETWEEN 8 AND 2048 AND base_url ~ '^https?://')),
    allowed_hosts      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_hosts) <= 16),
    destination_class  text        NOT NULL DEFAULT 'public' CHECK (destination_class IN ('public', 'internal')),
    access_mode        text        NOT NULL CHECK (access_mode IN ('pantherclaw_held', 'agent_held', 'target_enforced', 'none')),
    credential_header  text        CHECK (credential_header IS NULL OR credential_header ~ '^[A-Za-z0-9-]{1,64}$'),
    credential_scheme  text        CHECK (credential_scheme IS NULL OR credential_scheme ~ '^[A-Za-z0-9._-]{1,32}$'),
    default_mode       text        NOT NULL DEFAULT 'monitor' CHECK (default_mode IN ('monitor', 'enforce')),
    max_response_bytes integer     NOT NULL DEFAULT 1048576 CHECK (max_response_bytes BETWEEN 1024 AND 8388608),
    timeout_ms         integer     NOT NULL DEFAULT 10000 CHECK (timeout_ms BETWEEN 100 AND 60000),
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'QUARANTINED', 'RETIRED')),
    quarantine_reason  text        CHECK (quarantine_reason IS NULL OR quarantine_reason ~ '^[a-z0-9_]{1,64}$'),
    revision           integer     NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    CHECK ((kind = 'local') = (base_url IS NULL)),
    CHECK (kind <> 'local' OR access_mode = 'none'),
    CHECK (credential_header IS NOT NULL OR credential_scheme IS NULL),
    CHECK ((state = 'QUARANTINED') = (quarantine_reason IS NOT NULL))
);
-- A retired connection frees its name.
CREATE UNIQUE INDEX connections_name ON pc.connections (org_id, name) WHERE state <> 'RETIRED';
CREATE INDEX connections_gateway ON pc.connections (org_id, gateway_id) WHERE state <> 'RETIRED';

-- An explicit mode for one package route of a connection; routes without a
-- row use the connection's default_mode.
CREATE TABLE pc.connection_routes (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id uuid        NOT NULL,
    route         text        NOT NULL CHECK (route ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    mode          text        NOT NULL CHECK (mode IN ('monitor', 'enforce')),
    changed_by    text        NOT NULL CHECK (char_length(changed_by) BETWEEN 1 AND 100),
    changed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id, route),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

-- One sealed credential version of a connection (HR-060). sealed is the
-- crypto.Seal blob (version, length-prefixed X-Wing encapsulation of 1,120
-- bytes, AES-256-GCM ciphertext); its HPKE info binds org, connection,
-- version, allowed hosts, broker key and placement, so a row moved to
-- another connection, version or org does not open. At most one ACTIVE per
-- connection.
CREATE TABLE pc.credentials (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    version       integer     NOT NULL CHECK (version > 0),
    broker_key_id uuid        NOT NULL,
    sealed        bytea       NOT NULL CHECK (octet_length(sealed) BETWEEN 1140 AND 70000),
    allowed_hosts text[]      NOT NULL CHECK (cardinality(allowed_hosts) BETWEEN 1 AND 16),
    header        text        NOT NULL CHECK (header ~ '^[A-Za-z0-9-]{1,64}$'),
    scheme        text        CHECK (scheme IS NULL OR scheme ~ '^[A-Za-z0-9._-]{1,32}$'),
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    superseded_at timestamptz,
    revoked_by    text        CHECK (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 100),
    revoked_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, connection_id, version),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, broker_key_id) REFERENCES pc.broker_keys (org_id, id),
    CHECK ((state = 'SUPERSEDED') = (superseded_at IS NOT NULL)),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX credentials_active ON pc.credentials (org_id, connection_id) WHERE state = 'ACTIVE';

-- The circuit breaker a gateway reported for a connection (HR-078). OPEN
-- quarantines the connection; restoring the connection closes it.
CREATE TABLE pc.circuit_states (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id uuid        NOT NULL,
    gateway_id    uuid        NOT NULL,
    state         text        NOT NULL CHECK (state IN ('CLOSED', 'OPEN')),
    unknown_count integer     NOT NULL CHECK (unknown_count >= 0),
    total_count   integer     NOT NULL CHECK (total_count >= unknown_count),
    opened_at     timestamptz,
    closed_at     timestamptz,
    reported_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id, gateway_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    CHECK ((state = 'OPEN') = (opened_at IS NOT NULL AND closed_at IS NULL) OR state = 'CLOSED')
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connections', 'connection_routes', 'credentials', 'circuit_states']
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

GRANT SELECT, INSERT ON pc.connections, pc.connection_routes, pc.credentials, pc.circuit_states TO pc_app;
GRANT UPDATE (gateway_id, package, base_url, allowed_hosts, destination_class, access_mode, credential_header,
    credential_scheme, default_mode, max_response_bytes, timeout_ms, state, quarantine_reason, revision, updated_by,
    updated_at) ON pc.connections TO pc_app;
GRANT UPDATE (mode, changed_by, changed_at) ON pc.connection_routes TO pc_app;
GRANT UPDATE (state, superseded_at, revoked_by, revoked_at) ON pc.credentials TO pc_app;
GRANT UPDATE (state, unknown_count, total_count, opened_at, closed_at, reported_at) ON pc.circuit_states TO pc_app;
GRANT SELECT ON pc.connections, pc.connection_routes, pc.circuit_states TO pc_audit_ro;
-- Never the sealed bytes (HR-061).
GRANT SELECT (org_id, id, connection_id, version, broker_key_id, allowed_hosts, header, scheme, state, created_by,
    created_at, superseded_at, revoked_by, revoked_at) ON pc.credentials TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.circuit_states;
DROP TABLE pc.credentials;
DROP TABLE pc.connection_routes;
DROP TABLE pc.connections;
