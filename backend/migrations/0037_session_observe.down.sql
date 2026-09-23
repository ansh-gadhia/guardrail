-- Remove the grants first: role_permissions references permissions.
DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE key = 'session:observe');

DELETE FROM permissions WHERE key = 'session:observe';
