-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Replay inputs (G0 M7 design decision 11): one sealed row per evaluation,
-- written with its decision receipt.

-- name: InsertEvaluationInputs :exec
INSERT INTO pc.evaluation_inputs (org_id, transaction_id, evaluation, format_version, pipeline_version, inputs,
    inputs_sha256, truncated)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(format_version),
    sqlc.arg(pipeline_version), sqlc.narg(inputs), sqlc.arg(inputs_sha256), sqlc.arg(truncated));

-- name: GetEvaluationInputs :one
SELECT format_version, pipeline_version, inputs, inputs_sha256, truncated
FROM pc.evaluation_inputs
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND evaluation = sqlc.arg(evaluation);
