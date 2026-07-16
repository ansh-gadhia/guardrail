BEGIN;

DROP TRIGGER IF EXISTS trg_channels_updated ON notification_channels;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notification_channels;
ALTER TABLE devices DROP COLUMN IF EXISTS requires_approval;

COMMIT;
