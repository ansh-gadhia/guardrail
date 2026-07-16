-- seed.sql — idempotent bootstrap data: the permission catalogue, system role
-- templates, and a default organization. Safe to run repeatedly (ON CONFLICT).
-- Super Admin user bootstrap (with an Argon2id hash) is handled by the
-- `guardrail seed-admin` command in the IAM milestone, since hashing lives in
-- application code, not SQL.

BEGIN;

-- ---- Permission catalogue (resource:action) ----
INSERT INTO permissions (key, description) VALUES
    ('device:read',          'View devices'),
    ('device:write',         'Create/update/delete devices'),
    ('device:connect',       'Start a brokered session to a device'),
    ('credential:write',     'Create/rotate/delete credentials'),
    ('session:read',         'View access sessions'),
    ('session:terminate',    'Force-terminate active sessions'),
    ('recording:read',       'View/playback recordings'),
    ('recording:download',   'Download recordings'),
    ('recording:delete',     'Delete recordings'),
    ('log:read',             'View audit logs'),
    ('user:read',            'View users'),
    ('user:write',           'Create/update/delete users'),
    ('role:read',            'View roles'),
    ('role:write',           'Create/update/delete roles'),
    ('group:read',           'View asset groups'),
    ('group:write',          'Manage asset groups'),
    ('report:read',          'View/generate reports'),
    ('org:read',             'View organization settings'),
    ('org:write',            'Manage organization settings')
ON CONFLICT (key) DO NOTHING;

-- ---- System role templates (organization_id NULL, is_system true) ----
INSERT INTO roles (id, organization_id, name, description, is_system) VALUES
    ('10000000-0000-0000-0000-000000000001', NULL, 'Super Admin',        'Full cross-tenant administration', true),
    ('10000000-0000-0000-0000-000000000002', NULL, 'Organization Admin', 'Full administration within an org', true),
    ('10000000-0000-0000-0000-000000000003', NULL, 'Auditor',            'Read-only access to logs and recordings', true),
    ('10000000-0000-0000-0000-000000000004', NULL, 'Operator',           'Connect to devices and manage sessions', true),
    ('10000000-0000-0000-0000-000000000005', NULL, 'Read-only',          'View assets and sessions', true)
ON CONFLICT (id) DO NOTHING;

-- Organization Admin: everything except cross-tenant.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000002', p.id FROM permissions p
ON CONFLICT DO NOTHING;

-- Auditor: read logs, sessions, recordings.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000003', p.id FROM permissions p
WHERE p.key IN ('log:read', 'session:read', 'recording:read', 'report:read', 'device:read', 'user:read')
ON CONFLICT DO NOTHING;

-- Operator: connect + manage own sessions + read devices/credentials metadata.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000004', p.id FROM permissions p
WHERE p.key IN ('device:read', 'device:connect', 'session:read',
                'session:terminate', 'recording:read', 'group:read')
ON CONFLICT DO NOTHING;

-- Read-only: view assets and sessions.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000005', p.id FROM permissions p
WHERE p.key IN ('device:read', 'session:read', 'group:read', 'recording:read')
ON CONFLICT DO NOTHING;

-- ---- Default organization for local development ----
INSERT INTO organizations (id, name, slug, status) VALUES
    ('00000000-0000-0000-0000-0000000000aa', 'GuardRail Default', 'default', 'active')
ON CONFLICT (id) DO NOTHING;

COMMIT;
