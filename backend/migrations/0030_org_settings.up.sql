-- Per-organization settings, starting with recording retention.
--
-- Retention already existed as a number: every recording is stamped with a
-- retention_until 90 days out. Nothing ever read that column — there was no
-- purge job, no command, nothing — so the deadline was decorative and
-- recordings accumulated forever. A deployment could not answer "how long do
-- you keep session evidence?" with anything a court would accept, and the disk
-- had no ceiling.
--
-- The value lives here rather than only in the environment because retention is
-- a policy decision an administrator makes, not a deployment detail: it has to
-- be changeable without a redeploy, and it has to be per-tenant. The environment
-- still supplies the value this row is SEEDED with, so a fresh install obeys
-- .env and an existing one keeps whatever was set in the console.
CREATE TABLE org_settings (
    organization_id          UUID PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    -- 0 means keep recordings indefinitely. Explicit, because an absent value
    -- and "forever" are different answers and only one of them is a policy.
    recording_retention_days INTEGER NOT NULL DEFAULT 90 CHECK (recording_retention_days >= 0 AND recording_retention_days <= 3650),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by               UUID
);

ALTER TABLE org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY org_settings_isolation ON org_settings
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON org_settings TO guardrail_app;

-- The purge sweeps by deadline across every tenant, so it needs an index that
-- does not depend on the organization.
CREATE INDEX ix_recordings_retention ON recordings (retention_until)
    WHERE retention_until IS NOT NULL;
