-- Reverting drops the snapshot, which means sessions whose device has since been
-- deleted lose its name for good — the columns are the only surviving copy.
BEGIN;

DROP INDEX IF EXISTS ix_access_sessions_device_name;
ALTER TABLE access_sessions DROP COLUMN IF EXISTS device_address;
ALTER TABLE access_sessions DROP COLUMN IF EXISTS device_type;
ALTER TABLE access_sessions DROP COLUMN IF EXISTS device_name;

COMMIT;
