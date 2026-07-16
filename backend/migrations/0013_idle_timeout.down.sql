DROP INDEX IF EXISTS ix_access_sessions_idle;
ALTER TABLE access_sessions DROP COLUMN IF EXISTS last_activity_at;
ALTER TABLE devices DROP COLUMN IF EXISTS idle_timeout_minutes;
