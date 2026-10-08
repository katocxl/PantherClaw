-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Tenancy hierarchy (M2). Every query names org_id explicitly and runs in a
-- tenant transaction (forced RLS). Lists page by id (UUIDv7, creation
-- order; a zero cursor is sent as NULL, hence the coalesce). Changes are
-- conditional on the current state (HR-004); archiving
-- and attaching children lock the parent row so neither can race the other.

-- name: GetOrg :one
SELECT * FROM pc.orgs WHERE id = sqlc.arg(org_id);

-- name: UpdateOrgName :one
UPDATE pc.orgs SET name = sqlc.arg(name), updated_at = now()
WHERE id = sqlc.arg(org_id) AND state = 'ACTIVE'
RETURNING *;

-- name: InsertBusinessUnit :one
INSERT INTO pc.business_units (org_id, id, slug, name, description)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(slug), sqlc.arg(name), sqlc.arg(description))
RETURNING *;

-- name: GetBusinessUnit :one
SELECT * FROM pc.business_units WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockBusinessUnit :one
SELECT state FROM pc.business_units WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ShareBusinessUnit :one
SELECT state FROM pc.business_units WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;

-- name: ListBusinessUnits :many
SELECT * FROM pc.business_units
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (state = 'ACTIVE' OR sqlc.arg(include_archived)::bool)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: UpdateBusinessUnit :one
UPDATE pc.business_units
SET name = coalesce(sqlc.narg(name), name), description = coalesce(sqlc.narg(description), description), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: CountActiveTeamsInBusinessUnit :one
SELECT count(*) FROM pc.teams
WHERE org_id = sqlc.arg(org_id) AND business_unit_id = sqlc.arg(business_unit_id) AND state = 'ACTIVE';

-- name: ArchiveBusinessUnit :one
UPDATE pc.business_units SET state = 'ARCHIVED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: InsertTeam :one
INSERT INTO pc.teams (org_id, id, business_unit_id, slug, name, description)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(business_unit_id), sqlc.arg(slug), sqlc.arg(name), sqlc.arg(description))
RETURNING *;

-- name: GetTeam :one
SELECT * FROM pc.teams WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockTeam :one
SELECT state FROM pc.teams WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ShareTeam :one
SELECT state FROM pc.teams WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;

-- name: ListTeams :many
SELECT * FROM pc.teams
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.narg(business_unit_id)::uuid IS NULL OR business_unit_id = sqlc.narg(business_unit_id))
  AND (state = 'ACTIVE' OR sqlc.arg(include_archived)::bool)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: UpdateTeam :one
UPDATE pc.teams
SET name = coalesce(sqlc.narg(name), name), description = coalesce(sqlc.narg(description), description), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: CountActiveEnvironmentsInTeam :one
SELECT count(*) FROM pc.environments
WHERE org_id = sqlc.arg(org_id) AND team_id = sqlc.arg(team_id) AND state = 'ACTIVE';

-- name: ArchiveTeam :one
UPDATE pc.teams SET state = 'ARCHIVED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: InsertMembership :one
INSERT INTO pc.memberships (org_id, id, team_id, user_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(user_id))
RETURNING created_at;

-- name: DeleteMembership :execrows
DELETE FROM pc.memberships
WHERE org_id = sqlc.arg(org_id) AND team_id = sqlc.arg(team_id) AND user_id = sqlc.arg(user_id);

-- name: ListTeamMembers :many
SELECT m.id, m.user_id, m.created_at, u.email, u.display_name
FROM pc.memberships m
JOIN pc.users u ON u.org_id = m.org_id AND u.id = m.user_id
WHERE m.org_id = sqlc.arg(org_id) AND m.team_id = sqlc.arg(team_id) AND m.id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY m.id
LIMIT sqlc.arg(page_limit);

-- name: InsertEnvironment :one
INSERT INTO pc.environments (org_id, id, team_id, slug, name, description, kind)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(team_id), sqlc.arg(slug), sqlc.arg(name), sqlc.arg(description), sqlc.arg(kind))
RETURNING *;

-- name: GetEnvironment :one
SELECT * FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListEnvironments :many
SELECT * FROM pc.environments
WHERE org_id = sqlc.arg(org_id) AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (sqlc.narg(team_id)::uuid IS NULL OR team_id = sqlc.narg(team_id))
  AND (state = 'ACTIVE' OR sqlc.arg(include_archived)::bool)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: UpdateEnvironment :one
UPDATE pc.environments
SET name = coalesce(sqlc.narg(name), name), description = coalesce(sqlc.narg(description), description), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: ArchiveEnvironment :one
UPDATE pc.environments SET state = 'ARCHIVED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: ShareUser :one
SELECT * FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR SHARE;
