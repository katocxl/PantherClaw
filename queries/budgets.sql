-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Budget accounts and counters (M4 part 2, HR-048, HR-049). Rows are
-- ensured before finalization; finalization only runs the conditional
-- updates below, last, in the fixed (rank, id) order. A 0-row update means
-- the limit is reached and rolls the whole finalization back.

-- name: EnsureBudgetAccount :exec
INSERT INTO pc.budget_accounts (org_id, id, owner_kind, owner_id, rule, key_hash, period_start, rank, currency)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(owner_kind), sqlc.arg(owner_id), sqlc.arg(rule), sqlc.arg(key_hash),
        sqlc.arg(period_start), sqlc.arg(rank), sqlc.narg(currency))
ON CONFLICT (org_id, owner_id, rule, key_hash, period_start) DO NOTHING;

-- name: GetBudgetAccount :one
SELECT id, reserved, spent, reserved_count, spent_count
FROM pc.budget_accounts
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND key_hash = sqlc.arg(key_hash) AND period_start = sqlc.arg(period_start);

-- name: EnsureCounter :exec
INSERT INTO pc.counters (org_id, id, owner_kind, owner_id, rule, key_hash, window_start, rank)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(owner_kind), sqlc.arg(owner_id), sqlc.arg(rule), sqlc.arg(key_hash),
        sqlc.arg(window_start), sqlc.arg(rank))
ON CONFLICT (org_id, owner_id, rule, key_hash, window_start) DO NOTHING;

-- name: GetCounter :one
SELECT id, reserved, spent
FROM pc.counters
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND key_hash = sqlc.arg(key_hash) AND window_start = sqlc.arg(window_start);

-- name: CountCounterRows :one
SELECT count(*)::integer AS rows
FROM pc.counters
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND window_start = sqlc.arg(window_start);

-- name: ReserveBudgetAccount :execresult
UPDATE pc.budget_accounts
SET reserved = reserved + sqlc.arg(amount), reserved_count = reserved_count + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND (sqlc.narg(limit_amount)::numeric IS NULL OR spent + reserved + sqlc.arg(amount) <= sqlc.narg(limit_amount)::numeric)
  AND (sqlc.narg(max_count)::integer IS NULL OR spent_count + reserved_count + 1 <= sqlc.narg(max_count)::integer);

-- name: ReserveCounter :execresult
UPDATE pc.counters
SET reserved = reserved + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND reserved + spent + 1 <= sqlc.arg(max)
  AND (sqlc.narg(max_outstanding)::integer IS NULL OR reserved + 1 <= sqlc.narg(max_outstanding)::integer);

-- name: SettleBudgetAccount :execresult
UPDATE pc.budget_accounts
SET reserved = reserved - sqlc.arg(amount), reserved_count = reserved_count - 1,
    spent = spent + CASE WHEN sqlc.arg(commit)::boolean THEN sqlc.arg(amount) ELSE 0 END,
    spent_count = spent_count + CASE WHEN sqlc.arg(commit)::boolean THEN 1 ELSE 0 END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND reserved >= sqlc.arg(amount) AND reserved_count >= 1;

-- name: SettleCounter :execresult
UPDATE pc.counters
SET reserved = reserved - 1, spent = spent + CASE WHEN sqlc.arg(commit)::boolean THEN 1 ELSE 0 END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND reserved >= 1;

-- name: InsertReservation :exec
INSERT INTO pc.reservations (org_id, id, transaction_id, permit_id, account_id, counter_id, amount)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transaction_id), sqlc.arg(permit_id), sqlc.narg(account_id),
        sqlc.narg(counter_id), sqlc.arg(amount));

-- name: ListHeldReservations :many
SELECT id, account_id, counter_id, amount
FROM pc.reservations
WHERE org_id = sqlc.arg(org_id) AND permit_id = sqlc.arg(permit_id) AND state = 'HELD'
ORDER BY id;

-- name: SettleReservation :execresult
UPDATE pc.reservations SET state = sqlc.arg(to_state), settled_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'HELD';

-- ListOwnerBudgetAccounts returns the latest period of every budget
-- account the given grants and guardrails own.
-- name: ListOwnerBudgetAccounts :many
SELECT DISTINCT ON (owner_id, rule, key_hash)
       id, owner_kind, owner_id, rule, period_start, rank, currency, reserved, spent, reserved_count, spent_count
FROM pc.budget_accounts
WHERE org_id = sqlc.arg(org_id) AND owner_id = ANY(sqlc.arg(owner_ids)::uuid[])
ORDER BY owner_id, rule, key_hash, period_start DESC;
