BEGIN;

DROP POLICY IF EXISTS recording_artifacts_isolation ON recording_artifacts;
ALTER TABLE recording_artifacts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE recording_artifacts DISABLE ROW LEVEL SECURITY;

ALTER TABLE devices DROP COLUMN IF EXISTS created_by;
ALTER TABLE devices DROP COLUMN IF EXISTS record_sessions;

COMMIT;
