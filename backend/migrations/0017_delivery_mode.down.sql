-- Dropping delivery_mode would silently change how every isolated-but-unrecorded
-- device is served: they would fall back to the reverse proxy, which for an
-- appliance SPA means a blank screen, and for any device means the operator's
-- browser starts receiving the device's own DOM again. That is a change in the
-- security posture of live sessions, not a schema rollback.
--
-- Roll forward instead, or drop the column by hand once you have decided what
-- each isolated device should become.
DO $$
BEGIN
    RAISE EXCEPTION
        'refusing to drop devices.delivery_mode: isolated devices would silently revert to reverse-proxy delivery. Roll forward, or drop the column deliberately after reviewing each device.';
END
$$;
