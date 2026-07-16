-- 0012_device_recording: per-device session recording, plus the ownership needed
-- to govern it. Recording a session is a policy decision about a device, so it
-- belongs on the device: some targets warrant a full screen record, others are
-- noise or carry data that shouldn't be captured at all.

BEGIN;

-- Default true so existing devices keep today's behaviour (every session gets a
-- recording row) and so the safe posture is the one you get by not thinking
-- about it. Unticking is a deliberate act.
ALTER TABLE devices ADD COLUMN record_sessions BOOLEAN NOT NULL DEFAULT true;

-- created_by is who registered the device. It exists to answer "may this person
-- change the recording policy?" — the creator and super admins may, nobody else.
-- ON DELETE SET NULL: removing a person must not remove their devices, and a
-- device whose creator is gone simply falls to super-admin-only control.
ALTER TABLE devices ADD COLUMN created_by UUID REFERENCES users (id) ON DELETE SET NULL;

-- recording_artifacts had a GRANT but no RLS policy, so artifacts were reachable
-- across tenants at the DB level. It carries no organization_id of its own, so
-- the boundary is enforced through its parent recording.
ALTER TABLE recording_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE recording_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY recording_artifacts_isolation ON recording_artifacts
    USING (
        app_is_super_admin()
        OR EXISTS (
            SELECT 1 FROM recordings r
            WHERE r.id = recording_artifacts.recording_id
              AND r.organization_id = app_current_org()
        )
    );

COMMIT;
