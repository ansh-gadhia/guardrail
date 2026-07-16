BEGIN;

DROP TRIGGER IF EXISTS trg_asset_groups_updated ON asset_groups;
DROP TRIGGER IF EXISTS trg_credentials_updated ON credentials;
DROP TRIGGER IF EXISTS trg_devices_updated ON devices;

DROP TABLE IF EXISTS device_group_members;
DROP TABLE IF EXISTS asset_groups;
DROP TABLE IF EXISTS device_credentials;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS encryption_keys;

COMMIT;
