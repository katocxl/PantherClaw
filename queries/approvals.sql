-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approvals (G0 M5 part 2): what the decision pipeline reads about a held
-- transaction's approval request, its variants and the org's settings.

-- The latest request of the transaction for (run, action), with the open
-- evidence question and a proposed narrower action, if any.
-- name: LatestApprovalRequest :one
SELECT r.id, r.state, r.end_reason, r.binding, r.deadline_at, r.evidence_deadline_at, r.consume_by, r.display,
       coalesce((SELECT x.reason_code FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'REQUEST_EVIDENCE'
         ORDER BY x.created_at DESC LIMIT 1), '')::text AS question,
       (SELECT x.proposed_params FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'PROPOSE_NARROWER' LIMIT 1)::jsonb AS proposed
FROM pc.approval_requests r
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
WHERE r.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.action_id = sqlc.arg(action_id)
ORDER BY r.created_at DESC, r.id DESC
LIMIT 1;

-- Earlier requests for the same grant, operation and target (HR-037).
-- name: ApprovalVariants :many
SELECT id, created_at, state FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND variant_key = sqlc.arg(variant_key)
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Requests for the same operation and target approved in the 30 days
-- before now: context, never precedent (decision 9).
-- name: ApprovedForTarget :many
SELECT r.id, r.approved_at::timestamptz AS approved_at
FROM pc.approval_requests r
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
WHERE r.org_id = sqlc.arg(org_id) AND r.operation = sqlc.arg(operation) AND t.target_type = sqlc.arg(target_type)
  AND t.target_id = sqlc.arg(target_id) AND r.approved_at IS NOT NULL
  AND r.approved_at > sqlc.arg(now)::timestamptz - interval '30 days'
ORDER BY r.approved_at DESC, r.id DESC
LIMIT 5;

-- name: GetWaitlistSettings :one
SELECT * FROM pc.waitlist_settings WHERE org_id = sqlc.arg(org_id);

-- The launchers and principals of a run's ancestors, nearest first (runs
-- nest at most 8 deep).
-- name: RunAncestors :many
WITH RECURSIVE up (id, depth) AS (
    SELECT r.parent_run_id, 1 FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id)
    UNION ALL
    SELECT p.parent_run_id, up.depth + 1 FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.id
    WHERE up.depth < 9
)
SELECT p.launcher_user_id, p.launcher_sa_id, p.launcher_instance_id, p.principal_user_id, p.principal_sa_id
FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.id
ORDER BY up.depth;
