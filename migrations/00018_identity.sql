-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- PAP/1 workload identity (PAP-1 §3–§4, ADR-0013, ADR-0018, G0 M3):
-- single-use enrollment tokens (stored as SHA-256), trusted-issuer entries
-- as immutable revisions (HR-140, HR-141), agent instances (one Ed25519 key
-- each, bound for life to the issuer entry and claims they enrolled with,
-- HR-147), accepted attestations (their unique replay key makes every
-- attestation token single use, HR-143), per-org nonces (one per minute,
-- valid 5 minutes, HR-091) and the proof replay store, LIST-partitioned
-- into ten one-minute slots (HR-090). The issuer audience is pinned to the
-- org in the schema as a second line of defense.

-- +goose Up
CREATE TABLE pc.enrollment_tokens (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    agent_id       uuid        NOT NULL,
    environment_id uuid        NOT NULL,
    token_hash     bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    state          text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'USED', 'REVOKED')),
    created_by     text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    revoked_at     timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, token_hash),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id),
    -- PAP-1 §3.2: valid at most 15 minutes.
    CONSTRAINT enrollment_tokens_ttl CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    CONSTRAINT enrollment_tokens_used CHECK ((state = 'USED') = (used_at IS NOT NULL))
);

-- One row per revision of a trusted-issuer entry. Revisions never change
-- except their state; widening creates a PROPOSED revision that a human
-- activates (HR-141). One active and at most one proposed revision per entry.
CREATE TABLE pc.trusted_issuers (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    entry_id     uuid        NOT NULL,
    revision     integer     NOT NULL CHECK (revision >= 1),
    agent_id     uuid        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('github_actions', 'kubernetes')),
    issuer       text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    audience     text        NOT NULL,
    algorithms   text[]      NOT NULL CHECK (cardinality(algorithms) BETWEEN 1 AND 4),
    binding      jsonb       NOT NULL CHECK (jsonb_typeof(binding) = 'object' AND binding <> '{}'::jsonb
                                             AND octet_length(binding::text) <= 8192),
    auto_admit   boolean     NOT NULL DEFAULT false,
    widening     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(widening) = 'array'
                                                          AND octet_length(widening::text) <= 8192),
    state        text        NOT NULL CHECK (state IN ('PROPOSED', 'ACTIVE', 'SUPERSEDED', 'DISABLED', 'WITHDRAWN')),
    proposed_by  text        NOT NULL CHECK (char_length(proposed_by) BETWEEN 1 AND 100),
    proposed_at  timestamptz NOT NULL DEFAULT now(),
    activated_by text        CHECK (char_length(activated_by) BETWEEN 1 AND 100),
    activated_at timestamptz,
    closed_by    text        CHECK (char_length(closed_by) BETWEEN 1 AND 100),
    closed_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, entry_id, revision),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    -- HR-140: the audience is always this org's.
    CONSTRAINT trusted_issuers_audience CHECK (audience = 'pantherclaw:' || org_id::text),
    CONSTRAINT trusted_issuers_activation CHECK ((activated_at IS NULL) = (activated_by IS NULL)
        AND (state NOT IN ('ACTIVE', 'SUPERSEDED') OR activated_at IS NOT NULL))
);
CREATE UNIQUE INDEX trusted_issuers_one_active ON pc.trusted_issuers (org_id, entry_id) WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX trusted_issuers_one_proposed ON pc.trusted_issuers (org_id, entry_id) WHERE state = 'PROPOSED';
CREATE INDEX trusted_issuers_active_kind ON pc.trusted_issuers (org_id, kind) WHERE state = 'ACTIVE';

-- One workload key = one instance. The issuer revision and binding claims
-- an instance enrolled with never change (HR-147); L2 lasts until
-- attested_until (HR-143).
CREATE TABLE pc.agent_instances (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    agent_id            uuid        NOT NULL,
    jkt                 text        NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
    public_jwk          bytea       NOT NULL CHECK (octet_length(public_jwk) BETWEEN 2 AND 4096),
    state               text        NOT NULL CHECK (state IN ('PENDING_ADMISSION', 'ADMITTED', 'REJECTED',
                                                              'REVOKED', 'EXPIRED')),
    enrolled_via        text        NOT NULL CHECK (enrolled_via IN ('enrollment_token', 'attestation', 'discovery')),
    enrollment_token_id uuid,
    issuer_revision_id  uuid,
    binding             jsonb       CHECK (jsonb_typeof(binding) = 'object' AND octet_length(binding::text) <= 8192),
    att_level           smallint    NOT NULL DEFAULT 1 CHECK (att_level IN (1, 2)),
    attested_until      timestamptz,
    release_state       text        CHECK (release_state IN ('declared', 'attested')),
    release_digest      text        CHECK (release_digest ~ '^sha256:[0-9a-f]{64}$'),
    needs_review        boolean     NOT NULL DEFAULT false,
    last_network        text        CHECK (char_length(last_network) <= 64),
    last_seen_at        timestamptz,
    decided_by          text        CHECK (char_length(decided_by) BETWEEN 1 AND 100),
    decided_at          timestamptz,
    revoke_reason       text        CHECK (char_length(revoke_reason) <= 1000),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, jkt),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, enrollment_token_id) REFERENCES pc.enrollment_tokens (org_id, id),
    FOREIGN KEY (org_id, issuer_revision_id) REFERENCES pc.trusted_issuers (org_id, id),
    CONSTRAINT agent_instances_enrolled_via CHECK (
        (enrolled_via = 'enrollment_token') = (enrollment_token_id IS NOT NULL)
        AND (enrolled_via <> 'attestation' OR issuer_revision_id IS NOT NULL)),
    CONSTRAINT agent_instances_attested CHECK ((issuer_revision_id IS NULL) = (binding IS NULL)
        AND (att_level = 1 OR (issuer_revision_id IS NOT NULL AND attested_until IS NOT NULL)))
);
CREATE INDEX agent_instances_agent ON pc.agent_instances (org_id, agent_id, state);

-- Accepted attestations. The unique (issuer, token_key) makes each
-- attestation token single use (HR-143); token_key is the SHA-256 of the
-- token's jti, or of the token when it has none. Tokens are never stored.
CREATE TABLE pc.attestations (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    instance_id        uuid        NOT NULL,
    issuer_revision_id uuid        NOT NULL,
    issuer             text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    token_key          bytea       NOT NULL CHECK (octet_length(token_key) = 32),
    claims             jsonb       NOT NULL CHECK (jsonb_typeof(claims) = 'object'
                                                   AND octet_length(claims::text) <= 8192),
    release_digest     text        CHECK (release_digest ~ '^sha256:[0-9a-f]{64}$'),
    issued_at          timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    accepted_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, issuer, token_key),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, issuer_revision_id) REFERENCES pc.trusted_issuers (org_id, id),
    -- HR-143: at most one hour between issue and expiry.
    CONSTRAINT attestations_lifetime CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '1 hour')
);
CREATE INDEX attestations_instance ON pc.attestations (org_id, instance_id, accepted_at);

-- Server nonces (HR-091): one per org per minute, valid 5 minutes from the
-- start of the next minute at the latest. minute is the Unix minute.
CREATE TABLE pc.dpop_nonces (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    minute     bigint      NOT NULL CHECK (minute > 0),
    nonce      text        NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{22,64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, minute),
    UNIQUE (org_id, nonce)
);

-- Proof replay store (HR-090). The slot is the issue minute of the nonce the
-- proof carries modulo 10, so a replayed proof always lands in the same slot
-- and uniqueness per slot is enough. Rows are deleted once their nonce has
-- been expired for more than 60 seconds (PAP-1 §4), before the slot is
-- reused. No foreign key: this is the hottest insert on the request path.
CREATE TABLE pc.dpop_jti (
    org_id       uuid     NOT NULL,
    slot         smallint NOT NULL CHECK (slot BETWEEN 0 AND 9),
    jkt          text     NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
    jti          text     NOT NULL CHECK (char_length(jti) BETWEEN 22 AND 128),
    nonce_minute bigint   NOT NULL CHECK (nonce_minute > 0),
    CONSTRAINT dpop_jti_slot CHECK (slot = nonce_minute % 10),
    PRIMARY KEY (org_id, slot, jkt, jti)
) PARTITION BY LIST (slot);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOR s IN 0..9 LOOP
        EXECUTE format('CREATE TABLE pc.dpop_jti_%s PARTITION OF pc.dpop_jti FOR VALUES IN (%s)', s, s);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['enrollment_tokens', 'trusted_issuers', 'agent_instances', 'attestations',
                             'dpop_nonces', 'dpop_jti']
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

-- pc_app reaches the replay store only through the partitioned parent, where
-- the tenant policy applies; it holds no privilege on the partitions.
GRANT SELECT, INSERT ON pc.enrollment_tokens, pc.trusted_issuers, pc.agent_instances, pc.attestations,
    pc.dpop_nonces, pc.dpop_jti TO pc_app;
GRANT UPDATE (state, used_at, revoked_at) ON pc.enrollment_tokens TO pc_app;
GRANT UPDATE (state, activated_by, activated_at, closed_by, closed_at) ON pc.trusted_issuers TO pc_app;
GRANT UPDATE (state, att_level, attested_until, release_state, release_digest, needs_review, last_network,
    last_seen_at, decided_by, decided_at, revoke_reason, updated_at, expires_at) ON pc.agent_instances TO pc_app;
GRANT DELETE ON pc.dpop_nonces, pc.dpop_jti TO pc_app;
GRANT SELECT (org_id, id, agent_id, environment_id, state, created_by, created_at, expires_at, used_at, revoked_at)
    ON pc.enrollment_tokens TO pc_audit_ro;
GRANT SELECT ON pc.trusted_issuers, pc.agent_instances, pc.attestations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.dpop_jti;
DROP TABLE pc.dpop_nonces;
DROP TABLE pc.attestations;
DROP TABLE pc.agent_instances;
DROP TABLE pc.trusted_issuers;
DROP TABLE pc.enrollment_tokens;
