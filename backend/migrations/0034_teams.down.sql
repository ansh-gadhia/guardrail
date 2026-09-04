-- Reverse 0034.
--
-- Dropping the tables drops every team grant with them, so a user whose reach
-- came only from a team falls back to what their roles give — which for a
-- 'scoped' role with no grants of its own is nothing. That is the correct
-- direction for a rollback (reach narrows, never widens), but it is not a
-- silent one: re-applying 0034 does not bring the grants back.

BEGIN;

DROP TABLE IF EXISTS team_device_types;
DROP TABLE IF EXISTS team_asset_groups;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;

DROP FUNCTION IF EXISTS app_device_reach(UUID);
DROP FUNCTION IF EXISTS app_access_level(INT);
DROP FUNCTION IF EXISTS app_access_rank(TEXT);

-- The permission rows stay. role_permissions references them, and deleting a
-- permission an administrator has since granted to a custom role would revoke
-- that grant permanently — a rollback of the schema should not rewrite the
-- organization's RBAC. They are inert without the tables.

COMMIT;
