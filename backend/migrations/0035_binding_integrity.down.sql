-- Reverses 0035. Dropping the column loses every signature; the API will
-- re-sign every binding at its next startup, so this is safe to run.
BEGIN;
DROP INDEX IF EXISTS ix_groupcred_unsigned;
DROP INDEX IF EXISTS ix_devcred_unsigned;
ALTER TABLE group_credentials  DROP COLUMN IF EXISTS binding_mac;
ALTER TABLE device_credentials DROP COLUMN IF EXISTS binding_mac;
COMMIT;
