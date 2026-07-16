-- 0005_approvals_notify: optional per-device approval gating, notification
-- channels, and a transactional outbox for reliable notification delivery.

BEGIN;

ALTER TABLE devices ADD COLUMN requires_approval BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN ('email','slack','webhook')),
    config          JSONB NOT NULL DEFAULT '{}'::jsonb, -- target url / address (non-secret)
    events          TEXT[] NOT NULL DEFAULT '{}',        -- subscribed event keys ('*' = all)
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_channels_org ON notification_channels (organization_id);

-- Transactional outbox: notifications are enqueued in the same transaction as
-- the triggering change and dispatched asynchronously with retries.
CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    channel_id      UUID NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ
);
CREATE INDEX ix_notifications_pending ON notifications (status, created_at) WHERE status = 'pending';

CREATE TRIGGER trg_channels_updated BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels, notifications TO guardrail_app;

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY channels_isolation ON notification_channels
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

COMMIT;
