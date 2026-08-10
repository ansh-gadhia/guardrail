-- Reverting drops only the "how", not the "whether": record_sessions is
-- untouched, so every device stays recorded and falls back to the one capture
-- its protocol produced before this migration.
BEGIN;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_recording_kinds_check;
ALTER TABLE devices DROP COLUMN IF EXISTS recording_kinds;

COMMIT;
