-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Trusted fact providers and facts (HR-160; G0 M4 part 2, design decision
-- 11). A provider is bound to one service account and declares the facts it
-- may write; among active declarations each fact name has one provider. A
-- fact keeps the latest observation per (name, subject): an older
-- observation never replaces a newer one, which the upsert itself enforces.

-- +goose Up
CREATE TABLE pc.fact_providers (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    name               text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$'),
    service_account_id uuid        NOT NULL,
    state              text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED')),
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id)
);

CREATE TABLE pc.fact_declarations (
    org_id       uuid    NOT NULL,
    provider_id  uuid    NOT NULL,
    name         text    NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    value_type   text    NOT NULL CHECK (value_type IN ('boolean', 'integer', 'decimal', 'money', 'identifier', 'timestamp')),
    subject_type text    NOT NULL CHECK (subject_type ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$'),
    max_lag_s    integer NOT NULL CHECK (max_lag_s BETWEEN 1 AND 86400),
    active       boolean NOT NULL DEFAULT true,
    PRIMARY KEY (org_id, provider_id, name),
    FOREIGN KEY (org_id, provider_id) REFERENCES pc.fact_providers (org_id, id)
);
-- One active provider per fact name, compared with dots as underscores (the
-- name policies use).
CREATE UNIQUE INDEX fact_declarations_one_provider ON pc.fact_declarations (org_id, replace(name, '.', '_')) WHERE active;

CREATE TABLE pc.facts (
    org_id       uuid        NOT NULL,
    id           uuid        NOT NULL,
    name         text        NOT NULL,
    subject_type text        NOT NULL,
    subject_id   text        NOT NULL CHECK (char_length(subject_id) BETWEEN 1 AND 8192),
    provider_id  uuid        NOT NULL,
    value        bytea       NOT NULL CHECK (octet_length(value) BETWEEN 2 AND 1024),
    observed_at  timestamptz NOT NULL,
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name, subject_type, subject_id),
    FOREIGN KEY (org_id, provider_id) REFERENCES pc.fact_providers (org_id, id),
    CONSTRAINT facts_not_from_the_future CHECK (observed_at <= recorded_at)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['fact_providers', 'fact_declarations', 'facts']
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

GRANT SELECT, INSERT ON pc.fact_providers, pc.fact_declarations, pc.facts TO pc_app;
GRANT UPDATE (state) ON pc.fact_providers TO pc_app;
GRANT UPDATE (active) ON pc.fact_declarations TO pc_app;
GRANT UPDATE (provider_id, value, observed_at, recorded_at) ON pc.facts TO pc_app;
GRANT SELECT ON pc.fact_providers, pc.fact_declarations, pc.facts TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.facts;
DROP TABLE pc.fact_declarations;
DROP TABLE pc.fact_providers;
