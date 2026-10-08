-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: GetLicenceState :one
SELECT document, licence_id, rejected_reason, updated_at
FROM pc.licence_state
WHERE id = 1;

-- name: PutLicenceState :exec
INSERT INTO pc.licence_state (id, document, licence_id, rejected_reason, updated_at, updated_by)
VALUES (1, sqlc.narg(document), sqlc.narg(licence_id), sqlc.narg(rejected_reason), now(), sqlc.arg(updated_by))
ON CONFLICT (id) DO UPDATE
SET document = EXCLUDED.document, licence_id = EXCLUDED.licence_id,
    rejected_reason = EXCLUDED.rejected_reason, updated_at = now(), updated_by = EXCLUDED.updated_by;
