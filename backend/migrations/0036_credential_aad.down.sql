-- Reverses 0036.
--
-- DESTRUCTIVE IN ONE DIRECTION: rows already re-sealed as version 1 carry a tag
-- computed over an AAD. Dropping the column loses the record of that, and the
-- old code would open them with no AAD and fail. Roll back only alongside the
-- application, and only if no re-seal has run.
BEGIN;
DROP INDEX IF EXISTS ix_credentials_legacy_aad;
ALTER TABLE credentials DROP COLUMN IF EXISTS aad_version;
COMMIT;
