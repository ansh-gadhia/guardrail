-- 0011_must_change_password: first-login password change. A password an admin
-- typed for someone else is known to two people, so it is temporary by
-- definition: the console forces the owner to replace it before they can use
-- the platform.

BEGIN;

-- Default false so every existing account keeps working; only accounts created
-- from here on are marked.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;

COMMIT;
