-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Notifications (G0 M5 part 1, HR-157..159): channels, notifications rendered
-- from fixed templates, and one delivery per channel or personal recipient.
-- Channel secrets (the webhook signing secret, the Slack webhook URL) are
-- envelope ciphertexts whose AAD binds org, table, column and row (HR-062);
-- pc_audit_ro cannot read them. Deliveries carry only state; River jobs carry
-- (org_id, delivery_id). Old notifications and deliveries are deleted by the
-- notifications janitor (deliveries first).

-- +goose Up
CREATE TABLE pc.notification_channels (
    org_id                 uuid        NOT NULL REFERENCES pc.orgs (id),
    id                     uuid        NOT NULL,
    name                   text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    kind                   text        NOT NULL CHECK (kind IN ('log', 'email', 'slack', 'webhook')),
    state                  text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PAUSED', 'DISABLED')),
    pause_reason           text        CHECK (pause_reason IS NULL OR pause_reason IN ('MANUAL', 'FAILING', 'GONE')),
    event_types            text[]      NOT NULL CHECK (cardinality(event_types) BETWEEN 1 AND 32),
    min_severity           text        NOT NULL DEFAULT 'INFO' CHECK (min_severity IN ('INFO', 'WARNING', 'CRITICAL')),
    recipient_role         text        CHECK (recipient_role IS NULL OR recipient_role ~ '^[a-z_]{1,64}$'),
    url                    text        CHECK (url IS NULL OR (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%')),
    secret                 bytea       CHECK (secret IS NULL OR octet_length(secret) BETWEEN 16 AND 8192),
    prev_secret            bytea       CHECK (prev_secret IS NULL OR octet_length(prev_secret) BETWEEN 16 AND 8192),
    prev_secret_expires_at timestamptz,
    consecutive_failures   integer     NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    failing_since          timestamptz,
    last_success_at        timestamptz,
    last_failure_at        timestamptz,
    last_failure_code      text        CHECK (last_failure_code IS NULL OR last_failure_code ~ '^[a-z0-9_]{1,64}$'),
    created_by             text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CHECK ((kind = 'email') = (recipient_role IS NOT NULL)),
    CHECK ((kind = 'webhook') = (url IS NOT NULL)),
    CHECK ((kind IN ('slack', 'webhook')) = (secret IS NOT NULL)),
    CHECK (kind = 'webhook' OR prev_secret IS NULL),
    CHECK ((prev_secret IS NULL) = (prev_secret_expires_at IS NULL)),
    CHECK ((state = 'PAUSED') = (pause_reason IS NOT NULL)),
    CHECK ((consecutive_failures = 0) = (failing_since IS NULL))
);
-- A deleted (DISABLED) channel frees its name.
CREATE UNIQUE INDEX notification_channels_name ON pc.notification_channels (org_id, name) WHERE state <> 'DISABLED';

CREATE TABLE pc.notifications (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    type              text        NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$' AND char_length(type) <= 64),
    severity          text        NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    subject_type      text        CHECK (subject_type IS NULL OR subject_type ~ '^[a-z_]{1,32}$'),
    subject_id        uuid,
    title             text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body              text        NOT NULL CHECK (char_length(body) <= 2000),
    link_path         text        NOT NULL DEFAULT '' CHECK (link_path = '' OR (char_length(link_path) <= 512 AND link_path ~ '^/[A-Za-z0-9]')),
    recipient_user_id uuid,
    dedupe_key        text        CHECK (dedupe_key IS NULL OR char_length(dedupe_key) BETWEEN 1 AND 128),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, recipient_user_id) REFERENCES pc.users (org_id, id),
    CHECK ((subject_type IS NULL) = (subject_id IS NULL)),
    CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX notifications_dedupe ON pc.notifications (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX notifications_expiry ON pc.notifications (org_id, expires_at);

-- One delivery of a notification: to a channel (log, Slack, webhook), to one
-- user through an email channel, or to one user personally (no channel).
-- PENDING until it is DELIVERED, FAILED after its last attempt, EXPIRED with
-- its notification, SKIPPED (channel paused or email not configured),
-- DROPPED (channel queue full) or CANCELLED (channel deleted).
CREATE TABLE pc.deliveries (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    notification_id   uuid        NOT NULL,
    channel_id        uuid,
    recipient_user_id uuid,
    kind              text        NOT NULL CHECK (kind IN ('log', 'email', 'slack', 'webhook')),
    state             text        NOT NULL DEFAULT 'PENDING'
                                  CHECK (state IN ('PENDING', 'DELIVERED', 'FAILED', 'EXPIRED', 'SKIPPED', 'DROPPED', 'CANCELLED')),
    attempts          integer     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    next_attempt_at   timestamptz,
    last_attempt_at   timestamptz,
    last_status       integer     CHECK (last_status IS NULL OR last_status BETWEEN 100 AND 599),
    last_error        text        CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_]{1,64}$'),
    created_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, notification_id) REFERENCES pc.notifications (org_id, id),
    FOREIGN KEY (org_id, channel_id) REFERENCES pc.notification_channels (org_id, id),
    FOREIGN KEY (org_id, recipient_user_id) REFERENCES pc.users (org_id, id),
    CHECK (channel_id IS NOT NULL OR kind = 'email'),
    CHECK ((kind = 'email') = (recipient_user_id IS NOT NULL)),
    CHECK ((state = 'PENDING') = (finished_at IS NULL))
);
CREATE INDEX deliveries_channel_pending ON pc.deliveries (org_id, channel_id) WHERE state = 'PENDING';
CREATE INDEX deliveries_channel_recent ON pc.deliveries (org_id, channel_id, created_at DESC);
CREATE INDEX deliveries_notification ON pc.deliveries (org_id, notification_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['notification_channels', 'notifications', 'deliveries']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.notification_channels, pc.notifications, pc.deliveries TO pc_app;
GRANT UPDATE (name, state, pause_reason, event_types, min_severity, recipient_role, url, secret, prev_secret,
    prev_secret_expires_at, consecutive_failures, failing_since, last_success_at, last_failure_at, last_failure_code,
    updated_at) ON pc.notification_channels TO pc_app;
GRANT UPDATE (state, attempts, next_attempt_at, last_attempt_at, last_status, last_error, finished_at)
    ON pc.deliveries TO pc_app;
GRANT DELETE ON pc.notifications, pc.deliveries TO pc_app;
GRANT SELECT (org_id, id, name, kind, state, pause_reason, event_types, min_severity, recipient_role, url,
    prev_secret_expires_at, consecutive_failures, failing_since, last_success_at, last_failure_at, last_failure_code,
    created_by, created_at, updated_at) ON pc.notification_channels TO pc_audit_ro;
GRANT SELECT ON pc.notifications, pc.deliveries TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.deliveries;
DROP TABLE pc.notifications;
DROP TABLE pc.notification_channels;
