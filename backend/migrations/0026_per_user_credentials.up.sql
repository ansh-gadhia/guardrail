-- 0026_per_user_credentials: a device's credential can belong to a specific
-- person instead of to the device.
--
-- Until now a device owned exactly one credential and everybody entitled to the
-- device was injected with it. That is right for appliances with a single admin
-- login and wrong wherever operators hold named accounts on the target — the
-- device's own logs then record the shared account for every session, which
-- destroys the attribution the audit trail exists to provide.
--
-- Two scopes of binding, because binding per device does not survive contact
-- with reality: one named account usually works across every switch in a rack,
-- and thirty rows per person per rack is a set nobody maintains.
--
--   device_credentials  -- this credential, on this device
--   group_credentials   -- this credential, anywhere in this asset group's subtree
--
-- Defaults are inert: credential_mode = 'shared' reproduces today's behaviour
-- exactly, so an existing deployment upgrades and changes nothing.

BEGIN;

-- ---------------------------------------------------------------------------
-- Device: which model this device follows.
-- ---------------------------------------------------------------------------
ALTER TABLE devices ADD COLUMN credential_mode TEXT NOT NULL DEFAULT 'shared'
    CHECK (credential_mode IN ('shared', 'per_user'));

COMMENT ON COLUMN devices.credential_mode IS
    'shared: one vaulted credential for everyone entitled. per_user: each person '
    'is injected with their own named account; no fallback to the shared one.';

-- ---------------------------------------------------------------------------
-- Device-scoped bindings gain an owner.
-- ---------------------------------------------------------------------------
-- NULL user_id is the shared credential — the only kind that existed before, so
-- every current row means exactly what it meant yesterday.
ALTER TABLE device_credentials ADD COLUMN user_id UUID REFERENCES users (id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- Collapse pre-existing duplicate bindings.
-- ---------------------------------------------------------------------------
-- The old schema allowed a device to hold several credentials; only the
-- application kept it to one. So a real deployment has rows the new unique
-- index below would reject, and the migration has to settle them rather than
-- refuse to run.
--
-- Two kinds, and the first is the common one:
--
-- 1. Bindings to a SOFT-DELETED credential. Replacing a device's credential
--    soft-deletes the old one but leaves its binding row behind, so every
--    rotation since 0003 has left one of these. They are already invisible —
--    every read path joins credentials with deleted_at IS NULL — so deleting
--    them changes nothing anybody can observe.
DELETE FROM device_credentials dc
USING credentials c
WHERE c.id = dc.credential_id AND c.deleted_at IS NOT NULL;

-- 2. Genuinely several LIVE credentials on one device. Keep exactly the one the
--    old resolution would have picked (ORDER BY is_default DESC, created_at) so
--    that what the device authenticates with does not change, and drop the rest.
--    The credentials themselves are untouched: this removes a binding, not
--    secret material, so nothing becomes unrecoverable.
DELETE FROM device_credentials dc
WHERE EXISTS (
    SELECT 1
    FROM device_credentials other
    JOIN credentials oc ON oc.id = other.credential_id AND oc.deleted_at IS NULL
    JOIN credentials tc ON tc.id = dc.credential_id AND tc.deleted_at IS NULL
    WHERE other.device_id = dc.device_id
      AND other.credential_id <> dc.credential_id
      AND (other.is_default, oc.created_at) > (dc.is_default, tc.created_at)
);

-- is_default is dropped rather than left in place. With user_id present it can
-- no longer be answered without asking "default for whom?", and a flag that
-- cannot be answered is a second, contradictory source of truth for resolution.
-- Mode plus owner decide it now. Dropped AFTER the collapse above, which uses it
-- to decide which binding survives.
ALTER TABLE device_credentials DROP COLUMN IF EXISTS is_default;

-- The old primary key allowed one device to hold the same credential twice under
-- different owners, which is meaningless: a named account belongs to one person.
-- Replaced by the two rules that actually hold.
ALTER TABLE device_credentials DROP CONSTRAINT IF EXISTS device_credentials_pkey;
ALTER TABLE device_credentials ADD PRIMARY KEY (device_id, credential_id);

CREATE UNIQUE INDEX uq_devcred_shared ON device_credentials (device_id)
    WHERE user_id IS NULL;
CREATE UNIQUE INDEX uq_devcred_user ON device_credentials (device_id, user_id)
    WHERE user_id IS NOT NULL;
CREATE INDEX ix_devcred_user ON device_credentials (user_id) WHERE user_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Group-scoped bindings.
-- ---------------------------------------------------------------------------
-- Always owned: a group binding exists to say "this person's account works on
-- everything under here". A shared credential inherited across a subtree would
-- be a much larger claim — every device in the tree authenticating with one
-- secret — and is deliberately not expressible.
CREATE TABLE group_credentials (
    asset_group_id UUID NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    credential_id  UUID NOT NULL REFERENCES credentials (id) ON DELETE RESTRICT,
    user_id        UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_group_id, credential_id)
);
CREATE UNIQUE INDEX uq_groupcred_user ON group_credentials (asset_group_id, user_id);
CREATE INDEX ix_groupcred_user ON group_credentials (user_id);

-- Grant-only, no RLS of its own, mirroring device_group_members and the role
-- join tables from 0009: every asset_group_id a tenant can reach is already
-- gated by RLS on asset_groups at read time.
--
-- Note this covers reads only. A foreign key does NOT enforce the tenant
-- boundary on write, because FK checks bypass RLS — inserting a binding that
-- names another tenant's asset_group_id would satisfy the FK. The repository
-- sources ids through the RLS-protected parent on write; do the same for any
-- new writer here.
GRANT SELECT, INSERT, UPDATE, DELETE ON group_credentials TO guardrail_app;

COMMIT;
