BEGIN;

DROP POLICY IF EXISTS audit_write ON audit_events;
DROP POLICY IF EXISTS audit_read ON audit_events;
ALTER TABLE audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS roles_isolation ON roles;
DROP POLICY IF EXISTS users_isolation ON users;
DROP POLICY IF EXISTS org_isolation ON organizations;

ALTER TABLE roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE roles DISABLE ROW LEVEL SECURITY;
ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS app_is_super_admin();
DROP FUNCTION IF EXISTS app_current_org();

REVOKE ALL ON audit_events, organizations, users, roles, role_permissions,
    user_roles, auth_sessions, permissions FROM guardrail_app;
REVOKE USAGE ON SCHEMA public FROM guardrail_app;
-- Role is intentionally left in place (may own other grants); drop manually.

COMMIT;
