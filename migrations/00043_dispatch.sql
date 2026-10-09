-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- What the Authority binds for M6 dispatch (G0 M6 design decisions 10 and
-- 17, PAP-1 §7.3, HR-184, HR-186, HR-188). A transaction records its
-- channel and target, so an action token can name the target and only a
-- cooperative channel may report the outcome delegated; a re-evaluation
-- may change its mode. A permit records the outbound request the gateway
-- reported at BeginDispatch (method, URL and the SHA-256 of the exact
-- body) and the id of the action token minted over it. Rows written before
-- this migration keep NULLs.

-- +goose Up
ALTER TABLE pc.transactions
    ADD COLUMN channel     text CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook')),
    ADD COLUMN target_type text CHECK (target_type IS NULL OR char_length(target_type) BETWEEN 1 AND 128),
    ADD COLUMN target_id   text CHECK (target_id IS NULL OR char_length(target_id) BETWEEN 1 AND 8192);

ALTER TABLE pc.permits
    ADD COLUMN outbound_method      text  CHECK (outbound_method IS NULL OR outbound_method ~ '^[A-Z]{3,7}$'),
    ADD COLUMN outbound_url         text  CHECK (outbound_url IS NULL OR char_length(outbound_url) BETWEEN 1 AND 4096),
    ADD COLUMN outbound_body_sha256 bytea CHECK (outbound_body_sha256 IS NULL OR octet_length(outbound_body_sha256) = 32),
    ADD COLUMN action_token_jti     uuid,
    ADD CONSTRAINT permits_outbound CHECK ((outbound_method IS NULL) = (outbound_url IS NULL)),
    ADD CONSTRAINT permits_action_token CHECK (action_token_jti IS NULL OR outbound_body_sha256 IS NOT NULL);

GRANT UPDATE (mode) ON pc.transactions TO pc_app;
GRANT UPDATE (outbound_method, outbound_url, outbound_body_sha256, action_token_jti) ON pc.permits TO pc_app;

-- +goose Down
REVOKE UPDATE (outbound_method, outbound_url, outbound_body_sha256, action_token_jti) ON pc.permits FROM pc_app;
REVOKE UPDATE (mode) ON pc.transactions FROM pc_app;
ALTER TABLE pc.permits DROP CONSTRAINT permits_action_token, DROP CONSTRAINT permits_outbound,
    DROP COLUMN action_token_jti, DROP COLUMN outbound_body_sha256, DROP COLUMN outbound_url, DROP COLUMN outbound_method;
ALTER TABLE pc.transactions DROP COLUMN target_id, DROP COLUMN target_type, DROP COLUMN channel;
