-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Decisions of the M4 pipeline (G0 M4 part 2, design decisions 15-18):
-- idempotency lives in columns on transactions (HR-005, HR-006): an OPEN
-- transaction (REQUIRE_*, CANNOT_AUTHORIZE) is evaluated again, each
-- evaluation with its own decision receipt; a FINAL one (ALLOW, DENY) is
-- answered from storage. Permits no longer need an M1.5 budget, because
-- reservations record what they hold. dedupe_claims holds the latest attempt
-- on each irreversible action's dedupe key (HR-007).

-- +goose Up
ALTER TABLE pc.transactions
    ADD COLUMN state          text    NOT NULL DEFAULT 'FINAL' CHECK (state IN ('OPEN', 'FINAL')),
    ADD COLUMN evaluations    integer NOT NULL DEFAULT 1 CHECK (evaluations BETWEEN 1 AND 64),
    ADD COLUMN grant_id       uuid,
    ADD COLUMN grant_revision integer CHECK (grant_revision > 0),
    ADD COLUMN basis_digest   text    CHECK (basis_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN effective_hash bytea   CHECK (octet_length(effective_hash) = 32),
    ADD COLUMN dedupe_key     text    CHECK (dedupe_key ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT transactions_grant_fk FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id);

ALTER TABLE pc.decision_receipts ADD COLUMN evaluation integer NOT NULL DEFAULT 1 CHECK (evaluation BETWEEN 1 AND 64);
ALTER TABLE pc.decision_receipts DROP CONSTRAINT decision_receipts_pkey;
ALTER TABLE pc.decision_receipts ADD PRIMARY KEY (org_id, transaction_id, evaluation);

ALTER TABLE pc.permits ALTER COLUMN budget_id DROP NOT NULL, ALTER COLUMN amount DROP NOT NULL;

CREATE TABLE pc.dedupe_claims (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    dedupe_key     text        NOT NULL CHECK (dedupe_key ~ '^sha256:[0-9a-f]{64}$'),
    transaction_id uuid        NOT NULL,
    state          text        NOT NULL CHECK (state IN ('HELD', 'SUCCEEDED', 'RELEASED')),
    changed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, dedupe_key),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id)
);

ALTER TABLE pc.dedupe_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.dedupe_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.dedupe_claims
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT UPDATE (decision, reason_code, state, evaluations, grant_id, grant_revision, basis_digest, effective_hash)
    ON pc.transactions TO pc_app;
GRANT SELECT, INSERT ON pc.dedupe_claims TO pc_app;
GRANT UPDATE (transaction_id, state, changed_at) ON pc.dedupe_claims TO pc_app;
GRANT SELECT ON pc.dedupe_claims TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.dedupe_claims;
ALTER TABLE pc.permits ALTER COLUMN budget_id SET NOT NULL, ALTER COLUMN amount SET NOT NULL;
ALTER TABLE pc.decision_receipts DROP CONSTRAINT decision_receipts_pkey;
ALTER TABLE pc.decision_receipts ADD PRIMARY KEY (org_id, transaction_id);
ALTER TABLE pc.decision_receipts DROP COLUMN evaluation;
REVOKE UPDATE (decision, reason_code, state, evaluations, grant_id, grant_revision, basis_digest, effective_hash)
    ON pc.transactions FROM pc_app;
ALTER TABLE pc.transactions DROP CONSTRAINT transactions_grant_fk,
    DROP COLUMN dedupe_key, DROP COLUMN effective_hash, DROP COLUMN basis_digest, DROP COLUMN grant_revision,
    DROP COLUMN grant_id, DROP COLUMN evaluations, DROP COLUMN state;
