-- 0027_approval_hierarchy: rank roles, so an approval can be routed to somebody
-- who outranks the person asking.
--
-- Levels are seeded with gaps so a custom role can be slotted between two system
-- roles without renumbering everything that already exists.
--
-- A user's effective level is the MAX across their roles. That is the same union
-- rule 0009 already uses for device scope — one mental model for "what do this
-- person's roles add up to", not two.
--
-- Nothing reads this yet. The gate that consumes it lands in 0028; this
-- migration is deliberately inert so the hierarchy can be configured and
-- inspected before anything depends on it.

BEGIN;

ALTER TABLE roles ADD COLUMN approval_level INT NOT NULL DEFAULT 0;

COMMENT ON COLUMN roles.approval_level IS
    'Approval rank. An approver must outrank the requester STRICTLY, which is '
    'also what makes self-approval impossible: your own level is never greater '
    'than itself.';

UPDATE roles SET approval_level = 100 WHERE id = '10000000-0000-0000-0000-000000000001'; -- Super Admin
UPDATE roles SET approval_level =  50 WHERE id = '10000000-0000-0000-0000-000000000002'; -- Organization Admin
UPDATE roles SET approval_level =   0 WHERE id = '10000000-0000-0000-0000-000000000003'; -- Auditor
UPDATE roles SET approval_level =  10 WHERE id = '10000000-0000-0000-0000-000000000004'; -- Operator
UPDATE roles SET approval_level =   0 WHERE id = '10000000-0000-0000-0000-000000000005'; -- Read-only

-- ---------------------------------------------------------------------------
-- Permissions.
-- ---------------------------------------------------------------------------
-- decide and bypass are separate powers and are NOT the same check. An admin who
-- holds bypass skips the gate for their OWN connects; they still decide other
-- people's requests. Conflating them would delete the organization's entire
-- approval capacity the moment bypass was granted.
INSERT INTO permissions (key, description) VALUES
    ('approval:read',   'View access requests awaiting decision'),
    ('approval:decide', 'Approve or deny access requests'),
    ('approval:bypass', 'Connect to approval-gated devices without asking')
ON CONFLICT (key) DO NOTHING;

-- Organization Admin holds every permission (see db/seed.sql), so it picks up
-- all three. Existing deployments get them here rather than waiting for a
-- re-seed.
--
-- Sourced through a join on roles rather than naming the id directly. On a FRESH
-- database migrations run BEFORE db/seed.sql, so the system roles do not exist
-- yet — naming the id would violate the foreign key and abort the migration,
-- taking the whole install with it. Joining makes that case insert nothing, and
-- the seed then grants these permissions itself.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.id = '10000000-0000-0000-0000-000000000002'
  AND p.key IN ('approval:read', 'approval:decide', 'approval:bypass')
ON CONFLICT DO NOTHING;

-- Auditors watch; they do not decide.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.id = '10000000-0000-0000-0000-000000000003'
  AND p.key = 'approval:read'
ON CONFLICT DO NOTHING;

COMMIT;
