-- 0001_init: core IAM schema (organizations, users, roles, permissions) and the
-- append-only audit log. Later milestones add assets, vault, sessions, etc.
-- Tenant isolation policies (RLS) are applied in migration 0002.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid, digests
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive email

-- ---------------------------------------------------------------------------
-- Organizations (tenants)
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        CITEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'archived')),
    settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_org_slug ON organizations (slug) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Permissions catalogue (static, seeded). Keyed as "resource:action".
-- ---------------------------------------------------------------------------
CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------------------
-- Roles. System roles have organization_id = NULL and are shared templates;
-- custom roles belong to an organization.
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    is_system       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_role_name_per_org
    ON roles (COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    email              CITEXT NOT NULL,
    username           TEXT,
    password_hash      TEXT,                 -- Argon2id; NULL for federated users
    auth_provider      TEXT NOT NULL DEFAULT 'local'
                       CHECK (auth_provider IN ('local', 'ldap', 'oidc', 'saml')),
    external_id        TEXT,                 -- subject id from IdP
    status             TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'disabled', 'invited')),
    is_super_admin     BOOLEAN NOT NULL DEFAULT false,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    last_login_at      TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_user_email_per_org
    ON users (organization_id, email) WHERE deleted_at IS NULL;
CREATE INDEX ix_users_org ON users (organization_id) WHERE deleted_at IS NULL;

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- ---------------------------------------------------------------------------
-- Auth sessions (refresh-token families for rotation + reuse detection)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id          UUID NOT NULL,
    refresh_token_hash BYTEA NOT NULL,       -- SHA-256 of the opaque token
    user_agent         TEXT,
    ip                 INET,
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_auth_sessions_user ON auth_sessions (user_id);
CREATE UNIQUE INDEX uq_auth_refresh_hash ON auth_sessions (refresh_token_hash);

-- ---------------------------------------------------------------------------
-- Audit log: append-only, hash-chained per organization for tamper evidence.
-- The application DB role is granted INSERT/SELECT only (see 0002).
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations (id) ON DELETE RESTRICT,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id        UUID,
    actor_email     TEXT,
    action          TEXT NOT NULL,
    category        TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    session_id      UUID,
    ip              INET,
    user_agent      TEXT,
    result          TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash       BYTEA,
    hash            BYTEA NOT NULL
);
CREATE INDEX ix_audit_org_ts ON audit_events (organization_id, ts DESC);
CREATE INDEX ix_audit_action ON audit_events (action);
CREATE INDEX ix_audit_actor ON audit_events (actor_id, ts DESC);

-- keep updated_at fresh
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_org_updated  BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_roles_updated BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
