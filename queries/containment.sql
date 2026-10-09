-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The containment stream (G0 M6, HR-010): what each gateway of an org is
-- told about containment. The epoch and kill switch come from
-- GetContainmentNow (decisions.sql).

-- name: WatchedGateways :many
SELECT id, state, config_version FROM pc.gateways WHERE org_id = sqlc.arg(org_id);

-- name: WatchedConnections :many
SELECT id, gateway_id, state FROM pc.connections WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED';
