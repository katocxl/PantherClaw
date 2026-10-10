-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The canonical action of a held request (G0 M5 part 2, HR-172): a decider
-- who proposes a narrower action is checked against it (the same operation,
-- target, account and destinations; only material parameters, and only
-- toward narrower values), and the pipeline simulates the proposal from
-- it. It is the action the binding's action_hash covers, stored as it was
-- held and never shown: the page shows only the rendered display. The
-- constraint is NOT VALID, so requests held before this migration stay
-- readable; their proposals are refused.

-- +goose Up
ALTER TABLE pc.approval_requests
    ADD COLUMN action_ir bytea CHECK (octet_length(action_ir) BETWEEN 2 AND 65536),
    ADD CONSTRAINT approval_requests_action CHECK (subject_kind <> 'ACTION' OR action_ir IS NOT NULL) NOT VALID;

-- +goose Down
ALTER TABLE pc.approval_requests DROP CONSTRAINT approval_requests_action, DROP COLUMN action_ir;
