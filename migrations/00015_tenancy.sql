-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Tenancy (BUILD_GUIDE §8 M2, F573, F581): the org → business unit → team →
-- environment hierarchy, users linked to an OIDC identity (iss, sub), team
-- memberships, service accounts, role bindings and invitations. Every table
-- is tenant-scoped with composite keys and forced RLS (HR-050..053). Parents
-- never change after creation; archiving is a conditional state change
-- (HR-004). Invitation tokens are stored only as SHA-256 hashes.

-- +goose Up
CREATE TABLE pc.business_units (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    slug        text        NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ARCHIVED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, slug)
);

CREATE TABLE pc.teams (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    business_unit_id uuid,
    slug             text        NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name             text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description      text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    state            text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ARCHIVED')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, slug),
    FOREIGN KEY (org_id, business_unit_id) REFERENCES pc.business_units (org_id, id)
);

-- An environment belongs to the org (team_id NULL) or to one team; its slug
-- is unique under that parent.
CREATE TABLE pc.environments (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    team_id     uuid,
    slug        text        NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    kind        text        NOT NULL CHECK (kind IN ('DEVELOPMENT', 'STAGING', 'PRODUCTION')),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ARCHIVED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE NULLS NOT DISTINCT (org_id, team_id, slug),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id)
);

-- A user is one OIDC identity (issuer, subject) inside one org. Email and
-- display name are refreshed from the ID token at each login.
CREATE TABLE pc.users (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    issuer        text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    subject       text        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    email         text        NOT NULL DEFAULT '' CHECK (char_length(email) <= 320),
    display_name  text        NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 200),
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, issuer, subject)
);

CREATE TABLE pc.memberships (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    team_id    uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, team_id, user_id),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);

CREATE TABLE pc.service_accounts (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    name        text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED')),
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name)
);

-- One role for one principal (user or service account) at one scope. Roles
-- and their permissions are defined in code (internal/tenancy/domain).
CREATE TABLE pc.role_bindings (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    role               text        NOT NULL CHECK (role ~ '^[a-z][a-z_]{0,62}$'),
    user_id            uuid,
    service_account_id uuid,
    scope_type         text        NOT NULL CHECK (scope_type IN ('ORG', 'BUSINESS_UNIT', 'TEAM', 'ENVIRONMENT')),
    business_unit_id   uuid,
    team_id            uuid,
    environment_id     uuid,
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CONSTRAINT role_bindings_one_principal CHECK ((user_id IS NULL) <> (service_account_id IS NULL)),
    CONSTRAINT role_bindings_scope CHECK (CASE scope_type
        WHEN 'ORG' THEN business_unit_id IS NULL AND team_id IS NULL AND environment_id IS NULL
        WHEN 'BUSINESS_UNIT' THEN business_unit_id IS NOT NULL AND team_id IS NULL AND environment_id IS NULL
        WHEN 'TEAM' THEN team_id IS NOT NULL AND business_unit_id IS NULL AND environment_id IS NULL
        WHEN 'ENVIRONMENT' THEN environment_id IS NOT NULL AND business_unit_id IS NULL AND team_id IS NULL
    END),
    UNIQUE NULLS NOT DISTINCT (org_id, role, user_id, service_account_id, scope_type, business_unit_id, team_id, environment_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, business_unit_id) REFERENCES pc.business_units (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id)
);
CREATE INDEX role_bindings_user ON pc.role_bindings (org_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX role_bindings_service_account ON pc.role_bindings (org_id, service_account_id) WHERE service_account_id IS NOT NULL;

-- Single-use invitations. A MEMBER invitation is bound to an email; the
-- BOOTSTRAP invitation (created only by the operator command) grants Org
-- Admin and may be unbound. Expiry is checked against the database clock.
CREATE TABLE pc.invitations (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    kind             text        NOT NULL DEFAULT 'MEMBER' CHECK (kind IN ('MEMBER', 'BOOTSTRAP')),
    email            text        NOT NULL DEFAULT '' CHECK (char_length(email) <= 320),
    roles            text[]      NOT NULL CHECK (cardinality(roles) <= 16),
    token_hash       bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    state            text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACCEPTED', 'REVOKED')),
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    accepted_at      timestamptz,
    accepted_user_id uuid,
    revoked_at       timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, token_hash),
    CONSTRAINT invitations_member_has_email CHECK (kind = 'BOOTSTRAP' OR email <> ''),
    FOREIGN KEY (org_id, accepted_user_id) REFERENCES pc.users (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['business_units', 'teams', 'environments', 'users', 'memberships',
                             'service_accounts', 'role_bindings', 'invitations']
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

GRANT SELECT, INSERT ON pc.business_units, pc.teams, pc.environments, pc.users, pc.memberships,
    pc.service_accounts, pc.role_bindings, pc.invitations TO pc_app;
GRANT UPDATE (name, description, state, updated_at) ON pc.business_units, pc.teams, pc.environments TO pc_app;
GRANT UPDATE (email, display_name, state, updated_at, last_login_at) ON pc.users TO pc_app;
GRANT UPDATE (description, state, updated_at) ON pc.service_accounts TO pc_app;
GRANT UPDATE (state, accepted_at, accepted_user_id, revoked_at) ON pc.invitations TO pc_app;
GRANT DELETE ON pc.memberships, pc.role_bindings TO pc_app;
GRANT SELECT ON pc.business_units, pc.teams, pc.environments, pc.users, pc.memberships,
    pc.service_accounts, pc.role_bindings TO pc_audit_ro;
GRANT SELECT (org_id, id, kind, email, roles, state, created_by, created_at, expires_at, accepted_at,
    accepted_user_id, revoked_at) ON pc.invitations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.invitations;
DROP TABLE pc.role_bindings;
DROP TABLE pc.service_accounts;
DROP TABLE pc.memberships;
DROP TABLE pc.users;
DROP TABLE pc.environments;
DROP TABLE pc.teams;
DROP TABLE pc.business_units;
