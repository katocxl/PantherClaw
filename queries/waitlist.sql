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
