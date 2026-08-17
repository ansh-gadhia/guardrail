-- Reverse 0026_per_user_credentials.
--
-- Per-user bindings cannot be represented once user_id is gone, so they are
-- dropped rather than collapsed onto the device: silently promoting one
-- person's named account to the device's shared credential would hand it to
-- everybody entitled to the device.

BEGIN;

DROP TABLE IF EXISTS group_credentials;

DELETE FROM device_credentials WHERE user_id IS NOT NULL;

DROP INDEX IF EXISTS uq_devcred_shared;
DROP INDEX IF EXISTS uq_devcred_user;
DROP INDEX IF EXISTS ix_devcred_user;

ALTER TABLE device_credentials DROP COLUMN IF EXISTS user_id;
ALTER TABLE device_credentials ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT false;

-- Restore the pre-0026 default: the device's single remaining credential.
UPDATE device_credentials SET is_default = true;

ALTER TABLE devices DROP COLUMN IF EXISTS credential_mode;

COMMIT;
