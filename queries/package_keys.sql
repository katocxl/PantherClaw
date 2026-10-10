-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Org package-signing keys (HR-162, ADR-0020). Every write is conditional
-- on the state that was read (HR-004); imports, registrations and
-- revocations of one org are serialized by LockPackageImports.

-- LockPackageImports serializes an org's imports, key registrations and
-- revocations, so the one-signer-per-operation check and the active-key
-- limit cannot be raced (HR-162).
-- name: LockPackageImports :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.package_import:' || sqlc.arg(org_id)::text, 0));

-- name: InsertPackageSigningKey :exec
INSERT INTO pc.package_signing_keys (org_id, id, kid, public_key, name, state, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kid), sqlc.arg(public_key), sqlc.arg(name), 'ACTIVE', sqlc.arg(created_by));

-- name: CountPackageSigningKeys :one
SELECT count(*) FILTER (WHERE state = 'ACTIVE') AS active,
       count(*) FILTER (WHERE kid = sqlc.arg(kid)) AS same_kid
FROM pc.package_signing_keys
WHERE org_id = sqlc.arg(org_id);

-- name: GetPackageSigningKey :one
SELECT * FROM pc.package_signing_keys
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid);

-- name: GetPackageSigningKeyByID :one
SELECT * FROM pc.package_signing_keys
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListPackageSigningKeys :many
SELECT * FROM pc.package_signing_keys
WHERE org_id = sqlc.arg(org_id)
ORDER BY created_at DESC, id DESC
LIMIT 100;

-- name: RevokePackageSigningKey :one
UPDATE pc.package_signing_keys
SET state = 'REVOKED', revoke_reason = sqlc.arg(reason), revoked_by = sqlc.arg(revoked_by), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid) AND state = 'ACTIVE'
RETURNING id;

-- AdvancePackageKeyTrust records targets metadata accepted under a key,
-- only while the key is active and its state is what the import read.
-- name: AdvancePackageKeyTrust :execresult
UPDATE pc.package_signing_keys
SET metadata_version = sqlc.arg(version), metadata_digest = sqlc.arg(payload_digest), metadata_expires_at = sqlc.arg(expires_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
  AND metadata_version IS NOT DISTINCT FROM sqlc.narg(prev_version)::bigint
  AND metadata_digest IS NOT DISTINCT FROM sqlc.narg(prev_digest)::text;

-- OperationsTakenByOtherSigner lists the operations among ops that a
-- non-retired version from the other kind of signer defines: package-root
-- versions when org_signed, org-signed versions otherwise (HR-162).
-- name: OperationsTakenByOtherSigner :many
SELECT DISTINCT d.operation
FROM pc.action_definitions d
JOIN pc.package_versions v ON v.org_id = d.org_id AND v.id = d.version_id
WHERE d.org_id = sqlc.arg(org_id) AND d.operation = ANY(sqlc.arg(ops)::text[]) AND v.state <> 'RETIRED'
  AND (v.signing_key_id IS NULL) = sqlc.arg(org_signed)::boolean
ORDER BY 1;

-- name: ListVersionsSignedBy :many
SELECT v.id, t.name, v.version, v.state
FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND v.signing_key_id = sqlc.arg(key_id)
ORDER BY t.name, v.version
FOR UPDATE OF v;

-- name: GetVersionSigningKey :one
SELECT v.signing_key_id
FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name) AND v.version = sqlc.arg(version);
