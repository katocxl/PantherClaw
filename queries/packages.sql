-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Tool packages per org (M4 part 2). Every write is conditional on what
-- the use case read (HR-004); signed bytes and definitions are insert-only.

-- name: GetPackageTrust :one
SELECT version, payload_digest, expires_at
FROM pc.package_trust
WHERE org_id = sqlc.arg(org_id);

-- name: InsertPackageTrust :exec
INSERT INTO pc.package_trust (org_id, version, payload_digest, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(version), sqlc.arg(payload_digest), sqlc.arg(expires_at));

-- name: AdvancePackageTrust :execresult
UPDATE pc.package_trust
SET version = sqlc.arg(version), payload_digest = sqlc.arg(payload_digest), expires_at = sqlc.arg(expires_at), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND version = sqlc.arg(prev_version) AND payload_digest = sqlc.arg(prev_digest);

-- name: GetToolPackageID :one
SELECT id FROM pc.tool_packages
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name);

-- name: InsertToolPackage :exec
INSERT INTO pc.tool_packages (org_id, id, name) VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name));

-- name: GetPackagePin :one
SELECT p.version_id, p.version, p.digest
FROM pc.package_pins p
JOIN pc.tool_packages t ON t.org_id = p.org_id AND t.id = p.package_id
WHERE p.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name);

-- name: InsertPackagePin :exec
INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest)
VALUES (sqlc.arg(org_id), sqlc.arg(package_id), sqlc.arg(version_id), sqlc.arg(version), sqlc.arg(digest));

-- name: AdvancePackagePin :execresult
UPDATE pc.package_pins
SET version_id = sqlc.arg(version_id), version = sqlc.arg(version), digest = sqlc.arg(digest), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND package_id = sqlc.arg(package_id) AND version_id = sqlc.arg(prev_version_id);

-- name: InsertPackageVersion :exec
INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(package_id), sqlc.arg(version), sqlc.arg(file_digest),
        sqlc.arg(raw), sqlc.arg(state));

-- name: InsertActionDefinition :exec
INSERT INTO pc.action_definitions (org_id, id, version_id, operation, digest, canonical)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(operation), sqlc.arg(digest), sqlc.arg(canonical));

-- name: InsertConsequenceRule :exec
INSERT INTO pc.consequence_rules (org_id, id, version_id, position, canonical)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(position), sqlc.arg(canonical));

-- name: GetPackageVersionState :one
SELECT v.id, v.state
FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name) AND v.version = sqlc.arg(version);

-- name: TransitionPackageVersion :execresult
UPDATE pc.package_versions
SET state = sqlc.arg(to_state), changed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- GetDefinitionVersion finds the imported package version that holds a
-- definition pinned by an ActionIR (package, version, digest). Its
-- lifecycle state decides whether actions may use it.
-- name: GetDefinitionVersion :one
SELECT v.id, v.state
FROM pc.action_definitions d
JOIN pc.package_versions v ON v.org_id = d.org_id AND v.id = d.version_id
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE d.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name) AND v.version = sqlc.arg(version)
  AND d.digest = sqlc.arg(digest);

-- name: GetPackageVersionRaw :one
SELECT raw FROM pc.package_versions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListActiveVersionsWith :many
SELECT v.id, v.version
FROM pc.action_definitions d
JOIN pc.package_versions v ON v.org_id = d.org_id AND v.id = d.version_id
WHERE d.org_id = sqlc.arg(org_id) AND d.operation = sqlc.arg(operation) AND v.state = 'ACTIVE';

-- name: ListActiveVersions :many
SELECT id FROM pc.package_versions
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
ORDER BY id;

-- RaiseContainmentEpoch increments the org's containment epoch, so permits
-- issued before a removal of authority fail BeginDispatch (HR-002). Callers
-- run it as the first statement of their transaction (G0 M4 part 2,
-- design decision 8).
-- name: RaiseContainmentEpoch :execresult
UPDATE pc.org_containment
SET epoch = epoch + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id);
