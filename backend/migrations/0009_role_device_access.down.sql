-- Reverse 0009.

BEGIN;

DROP TABLE IF EXISTS role_asset_groups;
DROP TABLE IF EXISTS role_device_types;
ALTER TABLE roles DROP COLUMN IF EXISTS device_scope;

COMMIT;
