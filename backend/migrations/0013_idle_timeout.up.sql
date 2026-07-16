-- Per-device idle timeout: a brokered session that nobody is using is a live
-- credential-injected door left open. The session's granted window already caps
-- the total lifetime, but that is not the same control — a two-hour window on a
-- session abandoned after five minutes leaves one hour fifty-five minutes of
-- unattended privileged access to the device.
--
-- Minutes, not an interval: it is a small operator-facing number, it round-trips
-- to JSON and a form field without parsing, and it cannot express an ambiguous
-- unit. 0 means the device opts out of idle expiry entirely.
ALTER TABLE devices
    ADD COLUMN idle_timeout_minutes INT NOT NULL DEFAULT 60
        CHECK (idle_timeout_minutes BETWEEN 0 AND 1440);

-- last_activity_at is when the operator last actually did something in the
-- session, as opposed to when it started. NULL means nothing has happened yet,
-- and the reaper falls back to started_at so a session that is opened and
-- immediately abandoned still ages out.
ALTER TABLE access_sessions
    ADD COLUMN last_activity_at TIMESTAMPTZ;

-- The reaper sweeps active sessions every 30s; the partial index keeps that from
-- walking the whole history table, which only ever grows.
CREATE INDEX ix_access_sessions_idle
    ON access_sessions (last_activity_at)
    WHERE status = 'active';
