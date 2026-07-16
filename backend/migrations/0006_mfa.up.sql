-- 0006_mfa: multi-factor authentication. One enrolled method per user (TOTP for
-- now) plus single-use recovery codes. Both tables are keyed by user_id and, like
-- auth_sessions, are accessed via the trusted application path rather than the
-- per-tenant RLS GUC (the acting user is the subject of the row).

BEGIN;

CREATE TABLE user_mfa (
    user_id      UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    type         TEXT NOT NULL DEFAULT 'totp' CHECK (type IN ('totp')),
    secret       BYTEA NOT NULL,            -- envelope-encrypted TOTP shared secret
    confirmed_at TIMESTAMPTZ,               -- NULL until enrollment is verified
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  BYTEA NOT NULL,              -- SHA-256 of a single-use recovery code
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_recovery_codes_user ON user_recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TRIGGER trg_user_mfa_updated BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa, user_recovery_codes TO guardrail_app;

COMMIT;
