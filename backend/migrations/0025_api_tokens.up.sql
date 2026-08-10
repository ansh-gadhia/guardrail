-- 0025_api_tokens: long-lived credentials for machines, not people.
--
-- A monitoring board polling the device status feed had only one way in: log in
-- as a human every fifteen minutes, because that is when an access token
-- expires. That works and it is the wrong shape — every poll writes an
-- auth.login audit event, so a dashboard on a thirty-second interval buries the
-- audit trail of a PAM under ~2,900 rows a day of nothing happening. The trail
-- being readable is the product.
--
-- So: a token that authenticates directly, with no login, no expiry it has to
-- work around, and its own line in the audit log.
BEGIN;

CREATE TABLE api_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    -- SHA-256 of the token. The token itself is shown once, at creation, and is
    -- never recoverable — the same reason password_hash exists. A leaked
    -- database backup must not be a set of working credentials.
    --
    -- Plain SHA-256 rather than Argon2id, deliberately: this is a 256-bit random
    -- value, not a human-chosen password, so there is no dictionary to attack
    -- and nothing for a slow KDF to buy. It also has to be verified on every
    -- request, where Argon2's cost would be a self-inflicted rate limit.
    token_hash      BYTEA NOT NULL,
    -- The leading characters of the token, stored in clear so the console can
    -- show WHICH token a row refers to. Without it, revoking the right one out
    -- of five means guessing.
    prefix          TEXT NOT NULL,
    -- Permission keys this token carries. Constrained to reads at the
    -- application layer: access_sessions.user_id has a foreign key to users, so
    -- a token can never be the actor on a brokered session — and a machine
    -- credential that could open one is a much larger decision than this table.
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    created_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    -- NULL means no expiry. Explicit rather than implied: a token that silently
    -- stopped working at some unremembered date is an outage nobody can explain.
    expires_at      TIMESTAMPTZ,
    -- Stamped on use, throttled by the application. It answers the only question
    -- that matters at cleanup time: is anything still using this?
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The lookup on every authenticated request is by hash, so it must be indexed
-- and unique: two rows with one hash would make "which token is this" ambiguous.
CREATE UNIQUE INDEX uq_api_tokens_hash ON api_tokens (token_hash);
CREATE INDEX ix_api_tokens_org ON api_tokens (organization_id);

ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY api_tokens_isolation ON api_tokens
    USING (app_is_super_admin() OR organization_id = app_current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON api_tokens TO guardrail_app;

COMMIT;
