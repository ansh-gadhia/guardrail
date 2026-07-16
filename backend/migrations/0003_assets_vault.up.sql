-- 0003_assets_vault: target devices, the credential vault (envelope-encrypted),
-- device<->credential bindings, and asset groups. RLS scopes every table to the
-- owning organization, consistent with migration 0002.

BEGIN;

-- ---------------------------------------------------------------------------
-- KEK registry (no key material stored here; only metadata for rotation).
-- ---------------------------------------------------------------------------
CREATE TABLE encryption_keys (
    id         TEXT PRIMARY KEY,           -- e.g. 'env:1'
    provider   TEXT NOT NULL,              -- env | kms | vault
    alias      TEXT NOT NULL DEFAULT '',
    active     BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Devices (target HTTP/HTTPS admin interfaces).
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    vendor          TEXT NOT NULL DEFAULT '',
    device_type     TEXT NOT NULL DEFAULT '',
    host            TEXT NOT NULL,
    port            INT  NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    scheme          TEXT NOT NULL DEFAULT 'https' CHECK (scheme IN ('http','https')),
    verify_tls      BOOLEAN NOT NULL DEFAULT true,
    custom_headers  JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_device_endpoint
    ON devices (organization_id, host, port, scheme) WHERE deleted_at IS NULL;
CREATE INDEX ix_devices_org ON devices (organization_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_devices_tags ON devices USING GIN (tags);

-- ---------------------------------------------------------------------------
-- Credential vault. Secrets are stored ONLY as envelope-encrypted ciphertext:
--   secret_ciphertext = AES-256-GCM(plaintext, DEK, secret_nonce)
--   dek_wrapped       = AES-256-GCM(DEK, KEK[kek_id], dek_nonce)
-- Plaintext is never stored and never returned by any read path.
-- ---------------------------------------------------------------------------
CREATE TABLE credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    name              TEXT NOT NULL,
    type              TEXT NOT NULL CHECK (type IN ('password','api_key','certificate','client_cert')),
    username          TEXT NOT NULL DEFAULT '',
    injection         TEXT NOT NULL DEFAULT 'form' CHECK (injection IN ('form','basic','header','none')),
    secret_ciphertext BYTEA NOT NULL,
    secret_nonce      BYTEA NOT NULL,
    dek_wrapped       BYTEA NOT NULL,
    dek_nonce         BYTEA NOT NULL,
    kek_id            TEXT NOT NULL REFERENCES encryption_keys (id),
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    rotated_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ
);
CREATE INDEX ix_credentials_org ON credentials (organization_id) WHERE deleted_at IS NULL;

CREATE TABLE device_credentials (
    device_id     UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES credentials (id) ON DELETE RESTRICT,
    is_default    BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, credential_id)
);

-- ---------------------------------------------------------------------------
-- Asset groups (folders / dynamic), nestable, with device membership.
-- ---------------------------------------------------------------------------
CREATE TABLE asset_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    parent_id       UUID REFERENCES asset_groups (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'folder' CHECK (type IN ('folder','dynamic')),
    match_rules     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_asset_groups_org ON asset_groups (organization_id);

CREATE TABLE device_group_members (
    device_id      UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    asset_group_id UUID NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, asset_group_id)
);

-- Triggers to maintain updated_at.
CREATE TRIGGER trg_devices_updated BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_credentials_updated BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_asset_groups_updated BEFORE UPDATE ON asset_groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Grants + RLS for the least-privilege application role.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
    devices, credentials, device_credentials, asset_groups, device_group_members
    TO guardrail_app;
GRANT SELECT, INSERT, UPDATE ON encryption_keys TO guardrail_app;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['devices','credentials','asset_groups'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$CREATE POLICY %1$s_isolation ON %1$s
            USING (app_is_super_admin() OR organization_id = app_current_org())
            WITH CHECK (app_is_super_admin() OR organization_id = app_current_org())$f$, t);
    END LOOP;
END $$;

INSERT INTO encryption_keys (id, provider, alias, active) VALUES ('env:1','env','default',true)
    ON CONFLICT (id) DO NOTHING;

COMMIT;
