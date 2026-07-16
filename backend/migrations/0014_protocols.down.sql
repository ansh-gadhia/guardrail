-- Revert to web-only devices.
--
-- Rows using the new protocols/methods would violate the narrowed constraints,
-- so they must go first. Deleting a device would cascade into its sessions and
-- audit history, so refuse instead: a down-migration that silently destroys the
-- audit trail of every SSH session is worse than one that fails loudly.
DO $$
DECLARE
    n INT;
BEGIN
    SELECT count(*) INTO n FROM devices WHERE scheme NOT IN ('http', 'https');
    IF n > 0 THEN
        RAISE EXCEPTION 'cannot revert: % device(s) use ssh/rdp/vnc. Remove or convert them first.', n;
    END IF;
    SELECT count(*) INTO n FROM credentials WHERE injection IN ('ssh-password', 'ssh-key');
    IF n > 0 THEN
        RAISE EXCEPTION 'cannot revert: % credential(s) use SSH injection. Remove them first.', n;
    END IF;
END $$;

ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_injection_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_injection_check
    CHECK (injection IN ('form', 'basic', 'header', 'none'));

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_scheme_check;
ALTER TABLE devices ADD CONSTRAINT devices_scheme_check
    CHECK (scheme IN ('http', 'https'));
