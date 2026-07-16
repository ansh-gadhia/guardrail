-- 0009_role_device_access: resource-level device entitlement. A role now carries
-- a device scope — 'all' (every device in the org, the backward-compatible
-- default so existing roles keep working) or 'scoped' (restricted to an explicit
-- set of device types and/or asset groups). A user's effective access is the
-- union across all of their roles.

BEGIN;

ALTER TABLE roles ADD COLUMN device_scope TEXT NOT NULL DEFAULT 'all'
    CHECK (device_scope IN ('all', 'scoped'));

-- Role → allowed device types (e.g. 'router', 'firewall'). Only consulted for
-- roles whose device_scope = 'scoped'.
CREATE TABLE role_device_types (
    role_id     UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    device_type TEXT NOT NULL,
    PRIMARY KEY (role_id, device_type)
);

-- Role → granted asset groups. Membership is resolved through
-- device_group_members. Only consulted for 'scoped' roles.
CREATE TABLE role_asset_groups (
    role_id        UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    asset_group_id UUID NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, asset_group_id)
);

-- Grant-only, no RLS: these are join tables keyed on role_id, and RLS on roles
-- gates every role_id a tenant can reach on read. This mirrors
-- device_group_members from 0003.
--
-- Note this covers reads only. A foreign key does NOT enforce the tenant
-- boundary on write, because FK checks bypass RLS — inserting a grant that
-- names another tenant's asset_group_id would satisfy the FK. The repository
-- layer therefore sources ids through the RLS-protected parent table on write
-- (see RoleRepo.SetDeviceAccess); do the same for any new writer here.
GRANT SELECT, INSERT, UPDATE, DELETE ON role_device_types, role_asset_groups TO guardrail_app;

COMMIT;
