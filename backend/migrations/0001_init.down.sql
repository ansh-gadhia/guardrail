BEGIN;

DROP TRIGGER IF EXISTS trg_roles_updated ON roles;
DROP TRIGGER IF EXISTS trg_users_updated ON users;
DROP TRIGGER IF EXISTS trg_org_updated ON organizations;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS organizations;

COMMIT;
