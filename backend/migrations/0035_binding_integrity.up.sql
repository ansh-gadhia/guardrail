-- 0035_binding_integrity: prove a credential binding was written by GuardRail.
--
-- WHY THIS EXISTS
--
-- A credential row carries the secret. It does NOT carry the device or the
-- person it is for: that lives in device_credentials and group_credentials,
-- which are plain join rows with nothing but foreign keys.
--
-- So the cheapest way to steal a vaulted password was never to touch the
-- ciphertext at all. Insert one row —
--
--     INSERT INTO device_credentials (device_id, credential_id, user_id)
--     VALUES (<a device you may reach>, <the domain admin credential>, <you>);
--
-- — and press Connect. The credential row is untouched and still verifies,
-- row-level security is not violated because the device really is yours, and the
-- gateway injects the domain admin's password into your session. The audit trail
-- then records the account name from the row you named, so it reports the wrong
-- account for a use that did happen. Nothing in the system says no.
--
-- binding_mac is the thing that says no. It is HMAC-SHA256 over the binding's
-- own identity, keyed by a subkey derived from the vault master key, written by
-- the application whenever a binding is created or moved. A row inserted by hand
-- cannot carry a valid one, because producing it needs a key that lives only in
-- the API's memory — not in this database.
--
-- NULLABLE, DELIBERATELY
--
-- Every binding that already exists predates this column, and a device whose
-- session stops working because of a security upgrade is a worse outcome than
-- the hole being open one boot longer. The API signs every unsigned row at
-- startup (see SignUnsignedBindings) and only then enforces. That backfill is
-- idempotent and needs no operator action.
--
-- WHAT IT DOES NOT DO
--
-- Signing existing rows blesses whatever is there now, including a malicious
-- binding inserted before this ran. It is forward protection, not a repair. The
-- audit that prompted this found no such rows.

BEGIN;

ALTER TABLE device_credentials ADD COLUMN IF NOT EXISTS binding_mac BYTEA;
ALTER TABLE group_credentials  ADD COLUMN IF NOT EXISTS binding_mac BYTEA;

COMMENT ON COLUMN device_credentials.binding_mac IS
    'HMAC-SHA256 over (device_id, credential_id, user_id) keyed by a subkey of the vault master key. NULL only until the API backfills it at startup.';
COMMENT ON COLUMN group_credentials.binding_mac IS
    'HMAC-SHA256 over (asset_group_id, credential_id, user_id) keyed by a subkey of the vault master key. NULL only until the API backfills it at startup.';

-- Finding unsigned rows is the backfill's first query on every boot; without
-- this it is a sequential scan of every binding in the estate.
CREATE INDEX IF NOT EXISTS ix_devcred_unsigned
    ON device_credentials (device_id) WHERE binding_mac IS NULL;
CREATE INDEX IF NOT EXISTS ix_groupcred_unsigned
    ON group_credentials (asset_group_id) WHERE binding_mac IS NULL;

COMMIT;
