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

-- Granted by RANK, to roles that outrank an operator.
--
-- Not to everyone who can terminate a session, which was the first instinct and
-- is wrong: Operator holds session:terminate so that people can end their own
-- work, and deriving from it handed every operator the ability to watch their
-- colleagues type. That is peer surveillance, not supervision, and it is not
-- something a product should turn on for a whole role by default.
--
-- approval_level is the hierarchy this product already has — it is what decides
-- who may approve whose access request — so watching somebody work is granted to
-- the ranks that can already decide over them. 50 is Organization Admin; Super
-- Admin (100) bypasses permission checks anyway.
--
-- Auditors and read-only roles are deliberately excluded at any rank: they get
-- the recording, which is reviewable, already written, and cannot be used to
-- watch somebody in real time.
--
-- A deployment that genuinely wants an operator-level role watching — a NOC pairing
-- on an incident, say — grants this permission to a role in the console. That is a
-- decision somebody makes, not one the installer makes for them.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE p.key = 'session:observe'
  AND r.approval_level >= 50
ON CONFLICT DO NOTHING;
