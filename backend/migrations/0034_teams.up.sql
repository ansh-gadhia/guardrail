-- 0034_teams: teams, and the device reach a team confers.
--
-- WHY THIS EXISTS
--
-- Device reach already existed, but it lived on the ROLE (0009): a role is
-- 'all' or 'scoped', and a scoped role carries device types and asset groups.
-- That conflates two questions an organization answers separately — "what may
-- this person DO" (connect, terminate, download a recording, approve) and
-- "WHICH devices may they do it to". Expressing "the IT team reaches IT kit and
-- the security team reaches security kit" with roles alone means a role per team
-- per job function: IT Operator, IT Auditor, Security Operator, Security
-- Auditor, and a new one every time either axis grows. Roles multiply by teams,
-- and the permission set of "Operator" has to be kept identical across all of
-- them by hand.
--
-- A team is the second axis. Membership says which devices; the role continues
-- to say what may be done to them. Neither table grows when the other does.
--
-- WHAT A GRANT MEANS
--
-- Three levels, ordered: view < connect < manage.
--
--   view     the device is visible — inventory, dashboard counts, the status
--            feed — and nothing more
--   connect  visible, and a session may be brokered to it
--   manage   visible, connectable, and its configuration and credential
--            bindings may be edited
--
-- A level is a CEILING on reach, never a grant of capability: it can only ever
-- narrow what the role already permits. A team granting 'manage' over a group
-- gives an Auditor nothing an Auditor could not already do, because the Auditor
-- role holds no device:write. The two are ANDed at every enforcement point, and
-- that ordering is what keeps this from becoming a second, competing permission
-- system — the answer to "can I do X to device D" is always "does my role
-- permit X" AND "does my reach include D at a level that covers X".
--
-- BACKWARD COMPATIBILITY
--
-- Every existing deployment has no teams, and a user in no team is unaffected by
-- everything here: their reach is exactly the union their roles already gave
-- them. The seeded Organization Admin and Operator roles are device_scope='all'
-- and keep reaching every device at 'manage'.
--
-- One behaviour DOES change, deliberately, and only for deployments already
-- using scoped roles: out-of-reach devices are now hidden from listings rather
-- than merely refusing to connect. Before this migration a scoped role could
-- enumerate the entire inventory — names, addresses, ports, liveness — and was
-- stopped only at the Connect button. That is not what "scoped" was ever taken
-- to mean by anyone configuring it.

BEGIN;

-- ---------------------------------------------------------------------------
-- Level vocabulary
-- ---------------------------------------------------------------------------
-- Ranks rather than a Postgres enum: an enum cannot be extended inside a
-- transaction on older servers, and every comparison here is an ordering
-- ("at least connect"), which is what a rank expresses directly.
CREATE OR REPLACE FUNCTION app_access_rank(p_level TEXT)
RETURNS INT LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE p_level
        WHEN 'manage'  THEN 3
        WHEN 'connect' THEN 2
        WHEN 'view'    THEN 1
        ELSE 0
    END
$$;

CREATE OR REPLACE FUNCTION app_access_level(p_rank INT)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN p_rank >= 3 THEN 'manage'
        WHEN p_rank  = 2 THEN 'connect'
        WHEN p_rank  = 1 THEN 'view'
        ELSE 'none'
    END
$$;

-- ---------------------------------------------------------------------------
-- Teams
-- ---------------------------------------------------------------------------
CREATE TABLE teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    -- A blanket grant over every device in the organization, at this level.
    -- NULL means no blanket grant, which is the ordinary case.
    --
    -- This is what the question "somewhere the admin team has access to other
    -- groups' devices too" actually needs. Without it, an admin or platform team
    -- is enumerated against every asset group that exists, and silently stops
    -- reaching anything created afterwards — a grant that decays as the estate
    -- grows and gives no sign it has.
    all_devices_level TEXT CHECK (all_devices_level IN ('view','connect','manage')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_teams_org ON teams (organization_id);
-- Case-insensitive: "IT" and "it" as two teams in one organization is a
-- misconfiguration that reads as a typo forever afterwards.
CREATE UNIQUE INDEX uq_teams_org_name ON teams (organization_id, lower(name));

CREATE TRIGGER trg_teams_updated BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Membership
-- ---------------------------------------------------------------------------
-- A user may belong to several teams, and reach is the UNION over them. Union
-- and not intersection: a second team is always an addition, so adding someone
-- to a team can never take away what another team gave them. The alternative
-- makes "add them to the DR team as well" a change that quietly removes access
-- somewhere else, discovered during the incident the DR team was added for.
CREATE TABLE team_members (
    team_id  UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
-- The hot lookup is "what does THIS user reach", so user_id needs its own index;
-- the primary key only serves the team-first direction.
CREATE INDEX ix_team_members_user ON team_members (user_id);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
CREATE TABLE team_asset_groups (
    team_id        UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    asset_group_id UUID NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    access_level   TEXT NOT NULL DEFAULT 'connect'
                   CHECK (access_level IN ('view','connect','manage')),
    PRIMARY KEY (team_id, asset_group_id)
);
CREATE INDEX ix_team_asset_groups_group ON team_asset_groups (asset_group_id);

CREATE TABLE team_device_types (
    team_id      UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    device_type  TEXT NOT NULL,
    access_level TEXT NOT NULL DEFAULT 'connect'
                 CHECK (access_level IN ('view','connect','manage')),
    PRIMARY KEY (team_id, device_type)
);

-- ---------------------------------------------------------------------------
-- Effective reach
-- ---------------------------------------------------------------------------
-- ONE definition of the rule, used by every caller: the connect check, the
-- inventory listing, the dashboard counts and the status feed. They disagreed
-- before this migration — the connect check enforced scope and the listing did
-- not — and a rule written down twice is a rule that will differ again. Anything
-- that needs to know what a user reaches selects from here.
--
-- Returns one row per device the user reaches, with the highest rank any of
-- their roles or teams confers.
--
-- Asset-group grants include DESCENDANT groups, because a group tree that does
-- not inherit is a tree nobody can safely reorganise: moving a group under
-- another would silently revoke it. Note this applies to TEAM grants only —
-- role_asset_groups keeps the exact direct-membership meaning it has had since
-- 0009, because widening an existing grant is not something a schema migration
-- should do behind an administrator's back.
CREATE OR REPLACE FUNCTION app_device_reach(p_user UUID)
RETURNS TABLE (device_id UUID, access_rank INT)
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE
    -- Every team-granted group, expanded to itself plus everything beneath it,
    -- carrying the level granted at the root.
    granted (asset_group_id, access_rank) AS (
        SELECT tag.asset_group_id, app_access_rank(tag.access_level)
        FROM team_asset_groups tag
        JOIN team_members tm ON tm.team_id = tag.team_id AND tm.user_id = p_user
        UNION ALL
        SELECT child.id, g.access_rank
        FROM asset_groups child
        JOIN granted g ON child.parent_id = g.asset_group_id
    ),
    reach (device_id, access_rank) AS (
        -- An unrestricted role reaches every device, at manage. This is the
        -- backward-compatible arm: it is what every seeded role does today.
        SELECT d.id, 3
        FROM devices d
        WHERE d.deleted_at IS NULL
          AND EXISTS (
              SELECT 1 FROM user_roles ur
              JOIN roles r ON r.id = ur.role_id AND r.device_scope = 'all'
              WHERE ur.user_id = p_user
          )
        UNION ALL
        -- A scoped role, by device type. 'connect' because that is precisely
        -- what a 0009 grant has always permitted.
        SELECT d.id, 2
        FROM devices d
        JOIN role_device_types rdt ON lower(rdt.device_type) = lower(d.device_type)
        JOIN roles r ON r.id = rdt.role_id AND r.device_scope = 'scoped'
        JOIN user_roles ur ON ur.role_id = r.id AND ur.user_id = p_user
        WHERE d.deleted_at IS NULL
        UNION ALL
        -- A scoped role, by asset group. Direct membership only — see above.
        SELECT dgm.device_id, 2
        FROM role_asset_groups rag
        JOIN roles r ON r.id = rag.role_id AND r.device_scope = 'scoped'
        JOIN user_roles ur ON ur.role_id = r.id AND ur.user_id = p_user
        JOIN device_group_members dgm ON dgm.asset_group_id = rag.asset_group_id
        UNION ALL
        -- A team's blanket grant.
        SELECT d.id, app_access_rank(t.all_devices_level)
        FROM devices d
        JOIN teams t ON t.all_devices_level IS NOT NULL
        JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = p_user
        WHERE d.deleted_at IS NULL
        UNION ALL
        -- A team's asset-group grants, descendants included.
        SELECT dgm.device_id, g.access_rank
        FROM granted g
        JOIN device_group_members dgm ON dgm.asset_group_id = g.asset_group_id
        UNION ALL
        -- A team's device-type grants.
        SELECT d.id, app_access_rank(tdt.access_level)
        FROM devices d
        JOIN team_device_types tdt ON lower(tdt.device_type) = lower(d.device_type)
        JOIN team_members tm ON tm.team_id = tdt.team_id AND tm.user_id = p_user
        WHERE d.deleted_at IS NULL
    )
    SELECT reach.device_id, MAX(reach.access_rank)
    FROM reach
    GROUP BY reach.device_id
$$;

-- ---------------------------------------------------------------------------
-- Permissions
-- ---------------------------------------------------------------------------
-- Managing teams is managing who reaches what, which is the same power as
-- editing a role's scope — hence its own permission rather than folding into
-- user:write. seed.sql grants Organization Admin the whole catalogue, so these
-- reach that role on the next boot without being named again here.
INSERT INTO permissions (key, description) VALUES
    ('team:read',  'View teams and their device grants'),
    ('team:write', 'Create/update/delete teams, membership and grants')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Grants + RLS
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
    teams, team_members, team_asset_groups, team_device_types
    TO guardrail_app;
GRANT EXECUTE ON FUNCTION app_access_rank(TEXT)  TO guardrail_app;
GRANT EXECUTE ON FUNCTION app_access_level(INT)  TO guardrail_app;
GRANT EXECUTE ON FUNCTION app_device_reach(UUID) TO guardrail_app;

-- teams carries organization_id, so it takes the same isolation policy as every
-- other tenant table.
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams FORCE ROW LEVEL SECURITY;
CREATE POLICY teams_isolation ON teams
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

-- The three join tables are keyed on team_id and carry no organization of their
-- own, so RLS on teams gates every team_id a tenant can reach on READ. This
-- mirrors device_group_members (0003) and role_asset_groups (0009).
--
-- Reads only, and the distinction matters on write: a foreign-key check bypasses
-- RLS, so an FK alone would accept another tenant's user_id or asset_group_id.
-- Writers must source ids through the RLS-protected parent table and verify the
-- row count — see TeamRepo.SetMembers and TeamRepo.SetGrants.

COMMIT;
