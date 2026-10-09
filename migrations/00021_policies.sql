-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy bundles per org (G0 M4 part 2, design decision 20): a policy and
-- its immutable versions. An org has at most one published version at a
-- time; publishing supersedes the previous one in the same transaction.
-- pc_app may change only a version's state and publication fields, and
-- only conditionally (HR-004).

-- +goose Up
CREATE TABLE pc.policies (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    bundle_id  text        NOT NULL CHECK (bundle_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, bundle_id)
);

CREATE TABLE pc.policy_versions (
    org_id       uuid        NOT NULL,
    id           uuid        NOT NULL,
    policy_id    uuid        NOT NULL,
    version      integer     NOT NULL CHECK (version > 0),
    bundle       bytea       NOT NULL CHECK (octet_length(bundle) BETWEEN 2 AND 4194304),
    state        text        NOT NULL DEFAULT 'DRAFT' CHECK (state IN ('DRAFT', 'PUBLISHED', 'SUPERSEDED')),
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_by text        CHECK (char_length(published_by) BETWEEN 1 AND 128),
    published_at timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, policy_id, version),
    FOREIGN KEY (org_id, policy_id) REFERENCES pc.policies (org_id, id),
    CONSTRAINT policy_versions_published CHECK ((state = 'DRAFT') = (published_at IS NULL)
                                                AND (published_at IS NULL) = (published_by IS NULL))
);
CREATE UNIQUE INDEX policy_versions_one_published ON pc.policy_versions (org_id) WHERE state = 'PUBLISHED';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['policies', 'policy_versions']
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

GRANT SELECT, INSERT ON pc.policies, pc.policy_versions TO pc_app;
GRANT UPDATE (state, published_by, published_at) ON pc.policy_versions TO pc_app;
GRANT SELECT ON pc.policy_versions TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.policy_versions;
DROP TABLE pc.policies;
