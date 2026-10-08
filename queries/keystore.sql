-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: ListSigningKeys :many
SELECT id, kid, purpose, public_key, wrapped_private_key, kek_id, state
FROM pc.keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'REVOKED'
ORDER BY created_at, kid;

-- name: InsertSigningKey :exec
INSERT INTO pc.keys (org_id, id, kid, purpose, public_key, wrapped_private_key, kek_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kid), sqlc.arg(purpose), sqlc.arg(public_key),
        sqlc.arg(wrapped_private_key), sqlc.arg(kek_id), 'ACTIVE');

-- name: TransitionSigningKey :execresult
UPDATE pc.keys
SET state = sqlc.arg(to_state), state_changed_at = now()
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid) AND state = sqlc.arg(from_state);

-- name: LockKeystore :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.keystore:' || sqlc.arg(org_id)::uuid::text, 0));

-- name: ActiveDEK :one
SELECT version, wrapped_key
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose) AND state = 'ACTIVE';

-- name: GetDEK :one
SELECT wrapped_key
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose) AND version = sqlc.arg(version);

-- name: NextDEKVersion :one
SELECT (coalesce(max(version), 0) + 1)::integer AS version
FROM pc.deks
WHERE org_id = sqlc.arg(org_id) AND purpose = sqlc.arg(purpose);

-- name: InsertDEK :exec
INSERT INTO pc.deks (org_id, purpose, version, wrapped_key, kek_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(purpose), sqlc.arg(version), sqlc.arg(wrapped_key), sqlc.arg(kek_id), 'ACTIVE');
