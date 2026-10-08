-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Installed licence (global, one row). The document is signed and not
-- secret; it is re-verified against the embedded roots whenever it is
-- evaluated. A rejected licence is recorded with its reason so the server
-- runs with Community limits and the rejection is visible (T-034).

-- +goose Up
CREATE TABLE pc.licence_state (
    id               smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    document         text        CHECK (document IS NULL OR octet_length(document) <= 16384),
    licence_id       text        CHECK (licence_id IS NULL OR char_length(licence_id) <= 64),
    rejected_reason  text        CHECK (rejected_reason IS NULL OR char_length(rejected_reason) <= 256),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    updated_by       text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 256),
    CHECK (document IS NULL OR rejected_reason IS NULL)
);
GRANT SELECT, INSERT, UPDATE ON pc.licence_state TO pc_app;
GRANT SELECT ON pc.licence_state TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.licence_state;
