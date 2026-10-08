-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Authentication housekeeping (M2): expired client-assertion jtis (they can
-- no longer be replayed once their assertion expired), closed device codes,
-- and CLI sessions that ended more than 30 days ago. Audit evidence is in
-- the ledger and is not affected.

-- name: DeleteExpiredReplay :execrows
DELETE FROM pc.auth_replay WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 minute';

-- name: DeleteOldDeviceCodes :execrows
DELETE FROM pc.device_codes WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 day';

-- name: DeleteOldSessions :execrows
DELETE FROM pc.cli_sessions
WHERE org_id = sqlc.arg(org_id)
  AND ((state = 'REVOKED' AND revoked_at < now() - interval '30 days') OR expires_at < now() - interval '30 days');
