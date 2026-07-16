-- Separate HOW a session is delivered from WHETHER it is recorded.
--
-- These were one switch: record_sessions chose the recording policy AND, as a
-- side effect, the delivery mode — recorded devices went through browser
-- isolation, everything else through the reverse proxy. That conflated two
-- unrelated decisions and left the useful combination unreachable: isolation
-- without recording.
--
-- Isolation is worth having on its own. A full appliance SPA (a FortiGate, say)
-- cannot survive being re-served under a path prefix — its router resolves a
-- compiled-in base, and it navigates by means no proxy can intercept. Under
-- isolation the device loads at its own origin in a browser on the server and
-- simply works, whether or not anyone wants the video.
--
-- delivery_mode is a WEB-ONLY choice. A terminal or desktop device has exactly one
-- gateway and nothing to choose between, so it stores 'proxy' meaning "not
-- applicable" — as does the CHECK below, and for the same reason.
ALTER TABLE devices
    ADD COLUMN delivery_mode TEXT NOT NULL DEFAULT 'proxy'
        CHECK (delivery_mode IN ('proxy', 'isolated'));

-- Preserve today's behaviour exactly: every recorded WEB device was already being
-- delivered by isolation, so say so explicitly rather than changing what those
-- devices do. Non-web devices keep 'proxy'. An SSH device has never been rendered
-- in a browser and cannot be; marking it isolated would record a delivery mode it
-- has never had.
UPDATE devices SET delivery_mode = 'isolated'
    WHERE record_sessions = true AND scheme IN ('http', 'https');

-- Recording a WEB device implies isolation. Enforced in the database because the
-- application is not the only writer, and because the alternative to refusing the
-- row is a recording policy that reads "on" while no frame is ever captured.
--
-- Scoped to web schemes on purpose. The rule is not "recording implies a browser",
-- it is "recording implies a gateway that can capture" — and for SSH that gateway
-- is the SSH gateway itself, which keeps the session transcript with no browser
-- anywhere. A blanket constraint would refuse a recorded SSH device, which is both
-- legitimate and already supported.
ALTER TABLE devices
    ADD CONSTRAINT devices_recording_requires_isolation
        CHECK (
            scheme NOT IN ('http', 'https')
            OR NOT record_sessions
            OR delivery_mode = 'isolated'
        );

COMMENT ON COLUMN devices.delivery_mode IS
    'Web devices only. proxy = credential-injecting reverse proxy (device HTML re-served '
    'under /proxy/<sid>/); isolated = headless browser on the server, operator receives '
    'pixels. Recording a web device requires isolated. Non-web devices store proxy: they '
    'have one gateway and no delivery choice.';
