-- 0024_session_device_identity: a session remembers what it connected to.
--
-- access_sessions held only device_id, so every listing resolved the name by
-- joining devices. Delete the device and the join finds nothing: the session
-- history, the audit log and the recordings list all start showing a bare UUID
-- for a session that plainly had a name when it happened.
--
-- For an audit trail that is the wrong shape entirely. A record of who reached
-- what must not be rewritten by a later edit to the what — renaming a firewall
-- should not retitle last year's sessions, and removing it should not erase
-- them. So the identity is snapshotted onto the session at connect: this is what
-- the device was called, and where it lived, at the moment someone reached it.
--
-- device_id stays and stays a plain column (no FK was ever declared), so a
-- reviewer can still pivot to the device when it is still there.
BEGIN;

ALTER TABLE access_sessions ADD COLUMN device_name TEXT;
ALTER TABLE access_sessions ADD COLUMN device_type TEXT;
-- host:port as it was dialled. Recorded because "which box was that" is the
-- question a reviewer actually asks, and an address is the answer that survives
-- the device being renamed.
ALTER TABLE access_sessions ADD COLUMN device_address TEXT;

-- Backfill from the devices still present, including soft-deleted ones: their
-- rows are intact, so their names are recoverable now and would not be later.
UPDATE access_sessions s
SET device_name    = d.name,
    device_type    = NULLIF(d.device_type, ''),
    device_address = d.host || ':' || d.port
FROM devices d
WHERE d.id = s.device_id;

-- Left NULL where the device is genuinely gone. NULL means "not recorded",
-- which the API renders as the device id — the honest answer, and distinct from
-- an empty string that would read as a device with no name.
CREATE INDEX ix_access_sessions_device_name ON access_sessions (device_name)
    WHERE device_name IS NOT NULL;

COMMIT;
