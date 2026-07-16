-- 0007_device_allow_unmanaged: add a per-device break-glass flag.
--
-- GuardRail brokers access so a vaulted credential is injected server-side and
-- never reaches the user. A device with NO bound credential therefore has no
-- credential to inject, and connecting to it would just dump the user at the
-- device's own login page — defeating the platform's core guarantee. Connect is
-- now FAIL-CLOSED for such devices. This column is the explicit, audited opt-out:
-- set it true only for deliberate break-glass / no-auth targets.

BEGIN;

ALTER TABLE devices
    ADD COLUMN allow_unmanaged BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN devices.allow_unmanaged IS
    'Break-glass: permit a brokered session with no bound credential (no server-side injection). Default false = fail closed.';

COMMIT;
