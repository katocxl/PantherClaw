-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Notifications (G0 M5 part 1, HR-157..159). A notification and its
-- deliveries are inserted in the transaction of the change that caused
-- them (outbox); deliveries are then worked by River jobs that carry ids
-- only. Channel secrets are envelope ciphertexts (HR-062).

-- name: InsertChannel :exec
INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, min_severity, recipient_role, url, secret,
                                      created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(event_types), sqlc.arg(min_severity),
        sqlc.narg(recipient_role), sqlc.narg(url), sqlc.narg(secret), sqlc.arg(created_by));

-- name: ChannelsForRouting :many
SELECT id, kind, state, event_types, min_severity, recipient_role
FROM pc.notification_channels
WHERE org_id = sqlc.arg(org_id) AND state IN ('ACTIVE', 'PAUSED')
ORDER BY created_at, id;

-- name: PendingDeliveries :one
-- Counts a channel's pending deliveries, up to cap + 1.
SELECT count(*)::int FROM (
    SELECT 1 FROM pc.deliveries
    WHERE org_id = sqlc.arg(org_id) AND channel_id = sqlc.arg(channel_id) AND state = 'PENDING'
    LIMIT sqlc.arg(cap)::int + 1) p;

-- name: FlagChannelQueueFull :exec
UPDATE pc.notification_channels SET last_failure_at = now(), last_failure_code = 'queue_full', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ActiveUsersWithOrgRole :many
SELECT DISTINCT u.id
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = sqlc.arg(role) AND b.scope_type = 'ORG' AND u.state = 'ACTIVE'
ORDER BY u.id
LIMIT 500;

-- name: InsertNotification :execrows
INSERT INTO pc.notifications (org_id, id, type, severity, subject_type, subject_id, title, body, link_path,
                              recipient_user_id, dedupe_key, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(type), sqlc.arg(severity), sqlc.narg(subject_type), sqlc.narg(subject_id),
        sqlc.arg(title), sqlc.arg(body), sqlc.arg(link_path), sqlc.narg(recipient_user_id), sqlc.narg(dedupe_key),
        now() + make_interval(secs => sqlc.arg(ttl_seconds)::int))
ON CONFLICT (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING;

-- name: InsertDelivery :exec
INSERT INTO pc.deliveries (org_id, id, notification_id, channel_id, recipient_user_id, kind, state, last_error, finished_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(notification_id), sqlc.narg(channel_id), sqlc.narg(recipient_user_id),
        sqlc.arg(kind), sqlc.arg(state), sqlc.narg(last_error),
        CASE WHEN sqlc.arg(state)::text = 'PENDING' THEN NULL ELSE now() END);
