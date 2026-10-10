-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent Waitlist reads (M3: ADMISSION entries; PN-004.1). Entries are
-- decided by the service that owns their subject. evidence holds two
-- objects, "trusted" (established by PantherClaw) and "untrusted" (reported
-- by a workload or observed at a gateway), which are never mixed.

-- name: ListWaitlistEntries :many
SELECT * FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND state = ANY (sqlc.arg(states)::text[])
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: GetWaitlistEntry :one
SELECT * FROM pc.waitlist_entries WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Producers (G0 M5 part 2 slice 210). Each entry is opened in the
-- transaction that creates its subject; there is at most one open entry per
-- subject, so a producer that finds one returns it.
-- name: OpenWaitlistEntry :one
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, requested_by,
    evidence, priority, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(subject_type), sqlc.arg(subject_id), sqlc.narg(agent_id),
    sqlc.narg(run_id), sqlc.narg(transaction_id), sqlc.narg(requested_by), sqlc.arg(evidence), sqlc.arg(priority),
    sqlc.arg(deadline_at))
ON CONFLICT (org_id, subject_type, subject_id) WHERE state = 'OPEN' DO NOTHING
RETURNING id;

-- name: OpenEntryOf :one
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND subject_type = sqlc.arg(subject_type) AND subject_id = sqlc.arg(subject_id)
  AND state = 'OPEN';

-- name: CloseEntryOf :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND subject_type = sqlc.arg(subject_type)
  AND subject_id = sqlc.arg(subject_id) AND state = 'OPEN';

-- An unknown outcome's run and agent, for its RECONCILIATION entry.
-- name: TransactionOfRun :one
SELECT t.run_id, r.agent_id, t.operation
FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- Open entries past their deadline whose kind ends there (HR-177): an
-- access request or a tool review changes nothing when it expires.
-- name: ExpireWaitlistEntries :many
UPDATE pc.waitlist_entries
SET state = 'EXPIRED', decided_by = 'system', decided_at = now(), decision_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND kind = ANY (sqlc.arg(kinds)::text[]) AND deadline_at <= now()
RETURNING id, kind;

-- Assignment only shows who is working on an entry (HR-177).
-- name: AssignWaitlistEntry :execrows
UPDATE pc.waitlist_entries
SET assignee_user_id = sqlc.narg(assignee), assigned_at = CASE WHEN sqlc.narg(assignee)::uuid IS NULL THEN NULL ELSE now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN';
