-- Watching a colleague's live session is its own permission.
--
-- Not session:read. Seeing that a session exists — who is on which device, since
-- when — is what an auditor or a duty manager needs, and it is already widely
-- granted. Watching the keystrokes inside it is a different power over a
-- different subject: the person, not the estate. Folding the second into the
-- first would have silently handed live over-the-shoulder access to every
-- read-only and auditor role the moment the feature shipped.
INSERT INTO permissions (key, description) VALUES
    ('session:observe', 'Watch another user''s live session, read-only')
ON CONFLICT (key) DO NOTHING;

-- Granted to the roles that can already end somebody's session.
--
-- session:terminate is the closest existing power — it is the one that says "this
-- role supervises other people's work", and a role trusted to cut a session off
-- mid-command is not meaningfully more trusted by being allowed to watch it
-- first. Auditors and read-only roles are deliberately NOT included: they see the
-- record, which is reviewable and already written, not the live keyboard.
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, p.id
FROM role_permissions rp
JOIN permissions term ON term.id = rp.permission_id AND term.key = 'session:terminate'
CROSS JOIN permissions p
WHERE p.key = 'session:observe'
ON CONFLICT DO NOTHING;
