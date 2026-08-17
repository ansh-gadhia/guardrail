-- Reverse 0027_approval_hierarchy.

BEGIN;

DELETE FROM permissions WHERE key IN ('approval:read', 'approval:decide', 'approval:bypass');

ALTER TABLE roles DROP COLUMN IF EXISTS approval_level;

COMMIT;
