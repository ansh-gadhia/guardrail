-- 0002_rls: tenant isolation via PostgreSQL Row-Level Security, plus a
-- least-privilege application role. This is the second of GuardRail's two
-- tenant-isolation defenses (the first is the app-layer TenantScope). Even if
-- application code forgets a WHERE organization_id = ... clause, the database
-- refuses to return other tenants' rows.
--
-- The application sets, per transaction:
--     SET LOCAL app.current_org = '<org uuid>';
--     SET LOCAL app.is_super_admin = 'on'|'off';
-- Super Admin bypasses the org filter (audited at the app layer).

BEGIN;

-- Least-privilege role the API connects as. RLS is enforced for non-owner,
-- non-superuser roles; FORCE also enforces it for the table owner.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guardrail_app') THEN
        CREATE ROLE guardrail_app NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO guardrail_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    organizations, users, roles, role_permissions, user_roles, auth_sessions
    TO guardrail_app;
GRANT SELECT ON permissions TO guardrail_app;
-- Audit log is append-only for the application: no UPDATE/DELETE ever.
GRANT SELECT, INSERT ON audit_events TO guardrail_app;

-- Helper: current org from the session GUC (NULL when unset).
CREATE OR REPLACE FUNCTION app_current_org() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_org', true), '')::uuid;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION app_is_super_admin() RETURNS BOOLEAN AS $$
    SELECT COALESCE(current_setting('app.is_super_admin', true), 'off') = 'on';
$$ LANGUAGE sql STABLE;

-- Generic org-scoped policy applied to every tenant table.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['organizations', 'users', 'roles'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;

-- organizations: a tenant sees only its own org row; super admin sees all.
CREATE POLICY org_isolation ON organizations
    USING (app_is_super_admin() OR id = app_current_org())
    WITH CHECK (app_is_super_admin() OR id = app_current_org());

-- users / roles: scoped by organization_id (roles may be system-wide: org NULL).
CREATE POLICY users_isolation ON users
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

CREATE POLICY roles_isolation ON roles
    USING (app_is_super_admin() OR organization_id = app_current_org() OR organization_id IS NULL)
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

-- audit_events: enable RLS with read scoped to the org; inserts allowed for the
-- caller's org (or super admin / system events with NULL org).
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_events
    FOR SELECT
    USING (app_is_super_admin() OR organization_id = app_current_org());
CREATE POLICY audit_write ON audit_events
    FOR INSERT
    WITH CHECK (app_is_super_admin()
                OR organization_id = app_current_org()
                OR organization_id IS NULL);

COMMIT;
