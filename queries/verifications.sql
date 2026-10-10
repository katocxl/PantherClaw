-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Verification leases, observations and effect receipts (G0 M7 design
-- decisions 1-3, HR-190..192).

-- DueVerifications are the due tasks of the connections a gateway serves.
-- Reads stop when the kill switch is on or the connection is quarantined
-- or retired, as dispatches do (HR-190); target-log tasks are A9's.
-- name: DueVerifications :many
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.operation, v.request, v.attempts, v.deadline_at
FROM pc.verifications v
JOIN pc.connections c ON c.org_id = v.org_id AND c.id = v.connection_id
JOIN pc.org_containment o ON o.org_id = v.org_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PENDING' AND v.next_at <= now() AND v.deadline_at > now()
  AND v.transaction_id IS NOT NULL AND c.gateway_id = sqlc.arg(gateway_id) AND c.state = 'ACTIVE' AND NOT o.kill_switch
ORDER BY v.next_at
LIMIT sqlc.arg(max_tasks)
FOR UPDATE OF v SKIP LOCKED;

-- name: LeaseVerification :execrows
UPDATE pc.verifications
SET state = 'LEASED', lease_hash = sqlc.arg(lease_hash), leased_by = sqlc.arg(gateway_id), leased_at = now(),
    lease_expires_at = now() + make_interval(secs => sqlc.arg(lease_seconds)::float8), attempts = attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- LeasedVerification is a task under a live lease of this gateway, with
-- what its permit fixed (HR-190, HR-191): nothing else accepts a report.
-- name: LeasedVerification :one
SELECT v.id, v.purpose, v.transaction_id, v.connection_id, v.attempts, v.deadline_at,
       p.id AS permit_id, p.dispatching_at, p.definition_digest, p.verify_expect,
       t.effect_state, t.effect_level_required, t.effect_level_achieved
FROM pc.verifications v
JOIN pc.permits p ON p.org_id = v.org_id AND p.transaction_id = v.transaction_id
JOIN pc.transactions t ON t.org_id = v.org_id AND t.id = v.transaction_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.state = 'LEASED' AND v.leased_by = sqlc.arg(gateway_id)
  AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v;

-- name: FinishVerification :exec
UPDATE pc.verifications
SET state = sqlc.arg(state), finished_at = now(), lease_hash = NULL, leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'LEASED');

-- name: RetryVerification :exec
UPDATE pc.verifications
SET state = 'PENDING', next_at = now() + make_interval(secs => sqlc.arg(delay_seconds)::float8), lease_hash = NULL,
    leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'LEASED';

-- ReleaseExpiredLeases returns leases nobody reported in time to PENDING,
-- or ends them when the task's deadline passed too.
-- name: ReleaseExpiredLeases :many
UPDATE pc.verifications
SET state = CASE WHEN deadline_at <= now() THEN 'EXPIRED' ELSE 'PENDING' END,
    finished_at = CASE WHEN deadline_at <= now() THEN now() END,
    lease_hash = NULL, leased_by = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE org_id = sqlc.arg(org_id) AND state = 'LEASED' AND lease_expires_at < now()
RETURNING id, state, transaction_id;

-- name: ExpirePastDeadline :many
UPDATE pc.verifications
SET state = 'EXPIRED', finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING' AND deadline_at <= now()
RETURNING id, transaction_id;

-- name: TransactionEffect :one
SELECT t.effect_state, t.effect_level_required, t.effect_level_achieved, p.definition_digest
FROM pc.transactions t
JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id)
FOR UPDATE OF t;

-- name: NextEffectSeq :one
SELECT (coalesce(max(seq), 0) + 1)::integer FROM pc.effect_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id);

-- name: InsertEffectReceipt :exec
INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, level_achieved, basis, receipt_jws,
                                ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(seq), sqlc.arg(state), sqlc.arg(level_required),
        sqlc.narg(level_achieved), sqlc.arg(basis), sqlc.arg(receipt_jws), sqlc.arg(ledger_entry_id));

-- name: SetEffectState :exec
UPDATE pc.transactions SET effect_state = sqlc.arg(state), effect_level_achieved = sqlc.narg(achieved)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
