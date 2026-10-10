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

-- Access requests (decision 10). They grant nothing: a grant revision
-- citing the entry settles it, or a grant.issue holder dismisses it.
-- name: SettleAccessRequest :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'ACCESS_REQUEST' AND subject_type = 'grant'
  AND subject_id = sqlc.arg(grant_id) AND state = 'OPEN';

-- name: CountWorkloadAccessRequests :one
SELECT count(*)::integer FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND run_id = sqlc.arg(run_id) AND kind = 'ACCESS_REQUEST' AND requested_by LIKE 'instance:%';

-- A transaction of the run, with its decision and decisive reason.
-- name: RunTransaction :one
SELECT decision, reason_code FROM pc.transactions
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND run_id = sqlc.arg(run_id);

-- name: GrantCurrentRevision :one
SELECT current_revision FROM pc.grants WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Routing (G0 M5 part 2 slice 211, HR-173, decision 8). An open entry with
-- no next step time has not been routed yet.
-- name: UnroutedEntries :many
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND next_step_at IS NULL AND escalation_step = 0
ORDER BY priority, deadline_at, id
LIMIT sqlc.arg(lim);

-- name: EntryForRouting :one
SELECT e.id, e.kind, e.subject_type, e.subject_id, e.agent_id, e.requested_by, e.deadline_at, e.created_at,
       a.team_id, t.business_unit_id, a.environment_id
FROM pc.waitlist_entries e
LEFT JOIN pc.agents a ON a.org_id = e.org_id AND a.id = e.agent_id
LEFT JOIN pc.teams t ON t.org_id = a.org_id AND t.id = a.team_id
WHERE e.org_id = sqlc.arg(org_id) AND e.id = sqlc.arg(id) AND e.state = 'OPEN'
FOR UPDATE OF e;

-- The enabled people holding one of roles where the agent lives, with the
-- rank of their nearest binding: 0 environment or team, 1 business unit,
-- 2 org. An entry about no agent matches org bindings only.
-- name: DeciderCandidates :many
SELECT b.user_id::uuid AS user_id,
       min(CASE b.scope_type WHEN 'ORG' THEN 2 WHEN 'BUSINESS_UNIT' THEN 1 ELSE 0 END)::integer AS rank
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id AND u.state = 'ACTIVE'
WHERE b.org_id = sqlc.arg(org_id) AND b.role = ANY (sqlc.arg(roles)::text[])
  AND (b.scope_type = 'ORG'
    OR (b.scope_type = 'BUSINESS_UNIT' AND b.business_unit_id = sqlc.narg(business_unit_id)::uuid)
    OR (b.scope_type = 'TEAM' AND b.team_id = sqlc.narg(team_id)::uuid)
    OR (b.scope_type = 'ENVIRONMENT' AND b.environment_id = sqlc.narg(environment_id)::uuid))
GROUP BY b.user_id
ORDER BY rank, b.user_id
LIMIT sqlc.arg(lim);

-- name: InsertWaitlistRoute :exec
INSERT INTO pc.waitlist_routes (org_id, id, entry_id, step, kind, user_id, channel_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(entry_id), sqlc.arg(step), sqlc.arg(kind), sqlc.narg(user_id),
    sqlc.narg(channel_id));

-- name: SetEntryRouting :execrows
UPDATE pc.waitlist_entries
SET routing_health = sqlc.arg(health), escalation_step = sqlc.arg(step), next_step_at = sqlc.narg(next_step_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN';

-- The enabled people holding one of roles at org scope (the org's admins
-- for an unroutable entry).
-- name: OrgUsersWithRoles :many
SELECT DISTINCT u.id
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = ANY (sqlc.arg(roles)::text[]) AND b.scope_type = 'ORG' AND u.state = 'ACTIVE'
ORDER BY u.id
LIMIT 50;
