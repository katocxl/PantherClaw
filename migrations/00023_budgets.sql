-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Budget accounts, counters and reservations (G0 M4 part 2, design
-- decisions 9-10; HR-048, HR-049). An account or counter row is one rule of
-- one grant or guardrail, for one hashed grouping key and one period or
-- window; only the SHA-256 of the key is stored. Rows are created in a short
-- transaction before finalization, which then only updates them, last, in
-- the fixed (rank, id) order. The limit is the rule's current one, passed to
-- each conditional update, so a revised limit applies at once. Each row a
-- transaction reserves is a reservation, settled by the outcome. The M1.5
-- budgets table keeps serving the development grant until the pipeline
-- replaces it.

-- +goose Up
CREATE TABLE pc.budget_accounts (
    org_id         uuid          NOT NULL REFERENCES pc.orgs (id),
    id             uuid          NOT NULL,
    owner_kind     text          NOT NULL CHECK (owner_kind IN ('grant', 'envelope')),
    owner_id       uuid          NOT NULL,
    rule           text          NOT NULL CHECK (rule ~ '^[a-z][a-z0-9_]{0,31}$'),
    key_hash       bytea         NOT NULL CHECK (octet_length(key_hash) = 32),
    period_start   timestamptz   NOT NULL,
    rank           smallint      NOT NULL CHECK (rank BETWEEN 0 AND 5),
    currency       text          CHECK (currency ~ '^[A-Z]{3}$'),
    reserved       numeric(26,8) NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    spent          numeric(26,8) NOT NULL DEFAULT 0 CHECK (spent >= 0),
    reserved_count integer       NOT NULL DEFAULT 0 CHECK (reserved_count >= 0),
    spent_count    integer       NOT NULL DEFAULT 0 CHECK (spent_count >= 0),
    created_at     timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, owner_id, rule, key_hash, period_start)
);

CREATE TABLE pc.counters (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    owner_kind   text        NOT NULL CHECK (owner_kind IN ('grant', 'envelope')),
    owner_id     uuid        NOT NULL,
    rule         text        NOT NULL CHECK (rule ~ '^[a-z][a-z0-9_]{0,31}$'),
    key_hash     bytea       NOT NULL CHECK (octet_length(key_hash) = 32),
    window_start timestamptz NOT NULL,
    rank         smallint    NOT NULL CHECK (rank BETWEEN 0 AND 5),
    reserved     integer     NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    spent        integer     NOT NULL DEFAULT 0 CHECK (spent >= 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, owner_id, rule, key_hash, window_start)
);
CREATE INDEX counters_rule_window ON pc.counters (org_id, owner_id, rule, window_start);

CREATE TABLE pc.reservations (
    org_id         uuid          NOT NULL,
    id             uuid          NOT NULL,
    transaction_id uuid          NOT NULL,
    permit_id      uuid          NOT NULL,
    account_id     uuid,
    counter_id     uuid,
    amount         numeric(26,8) NOT NULL DEFAULT 0 CHECK (amount >= 0),
    state          text          NOT NULL DEFAULT 'HELD' CHECK (state IN ('HELD', 'COMMITTED', 'RELEASED')),
    created_at     timestamptz   NOT NULL DEFAULT now(),
    settled_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, permit_id) REFERENCES pc.permits (org_id, id),
    FOREIGN KEY (org_id, account_id) REFERENCES pc.budget_accounts (org_id, id),
    FOREIGN KEY (org_id, counter_id) REFERENCES pc.counters (org_id, id),
    CONSTRAINT reservations_one_row CHECK (num_nonnulls(account_id, counter_id) = 1),
    CONSTRAINT reservations_settled CHECK ((state = 'HELD') = (settled_at IS NULL))
);
CREATE INDEX reservations_permit ON pc.reservations (org_id, permit_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['budget_accounts', 'counters', 'reservations']
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

GRANT SELECT, INSERT ON pc.budget_accounts, pc.counters, pc.reservations TO pc_app;
GRANT UPDATE (reserved, spent, reserved_count, spent_count) ON pc.budget_accounts TO pc_app;
GRANT UPDATE (reserved, spent) ON pc.counters TO pc_app;
GRANT UPDATE (state, settled_at) ON pc.reservations TO pc_app;
GRANT SELECT ON pc.budget_accounts, pc.counters, pc.reservations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.reservations;
DROP TABLE pc.counters;
DROP TABLE pc.budget_accounts;
