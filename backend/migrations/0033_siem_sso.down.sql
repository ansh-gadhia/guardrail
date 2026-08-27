ALTER TABLE auth_sessions DROP COLUMN IF EXISTS sso;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_auth_provider_check;
-- Any account provisioned through the SIEM would violate the narrower check, so
-- it is put back to a provider that exists in it before the constraint returns.
-- 'oidc' rather than 'local': these accounts have no password hash, and calling
-- them local would offer their owners a password change that cannot work.
UPDATE users SET auth_provider = 'oidc' WHERE auth_provider = 'siem';
ALTER TABLE users ADD CONSTRAINT users_auth_provider_check
    CHECK (auth_provider IN ('local', 'ldap', 'oidc', 'saml'));

DROP INDEX IF EXISTS uq_users_siem_sub;
ALTER TABLE users DROP COLUMN IF EXISTS sso_source_role;
ALTER TABLE users DROP COLUMN IF EXISTS sso_managed;
ALTER TABLE users DROP COLUMN IF EXISTS siem_sub;
