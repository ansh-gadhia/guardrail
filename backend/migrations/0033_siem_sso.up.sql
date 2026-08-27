-- SIEM single sign-on: the link between a GuardRail account and the SIEM's idea
-- of the same person, plus the marker that says a session was vouched for by the
-- SIEM rather than by a password.
--
-- Three columns and one flag. No backfill, and nothing here changes the meaning
-- of a row that already exists: every existing account keeps siem_sub NULL and
-- sso_managed false, which is exactly "this account has nothing to do with the
-- SIEM" — the truth for all of them until somebody signs in through it.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

-- siem_sub is the SIEM's immutable user id, and it is what an account is FOUND
-- by once it has one.
--
-- Not the email address, and the difference is not academic. Email is a display
-- attribute that changes — a surname changes, a company migrates domains, an
-- address is corrected — and an account keyed on it is orphaned by every one of
-- those. The next sign-in finds nothing, provisions a second account, and the
-- original's roles, approval rank, saved state and history now belong to a user
-- who can no longer reach them. Nothing errors at any point. It surfaces weeks
-- later as "why can't I get to anything any more", by which time the trail from
-- cause to effect is cold.
--
-- Nullable, because most accounts have no SIEM identity at all: locally created
-- users, LDAP users, the installation account. They adopt one lazily, each on
-- its owner's next SIEM sign-in, so there is no migration window and no
-- coordinated cutover — see the backfill in app/iam.reconcileSSOIdentity.
ALTER TABLE users ADD COLUMN IF NOT EXISTS siem_sub TEXT;

-- Unique so two accounts can never claim the same SIEM identity. PARTIAL so the
-- NULLs do not collide with each other: in Postgres a NULL is never equal to
-- another NULL, so a plain unique index would in fact permit them — but the
-- partial predicate says the intent out loud and keeps the index to the handful
-- of rows that actually carry a subject.
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_siem_sub
    ON users (siem_sub) WHERE siem_sub IS NOT NULL AND deleted_at IS NULL;

-- sso_managed is the ownership boundary: does this account's role assignment
-- track the SIEM, or has a GuardRail administrator taken it over?
--
-- DEFAULT false matters. Without it every pre-existing account — including ones
-- an administrator granted roles to by hand — would be handed to the SIEM to
-- overwrite on the first sign-in that happened to match by email.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_managed BOOLEAN NOT NULL DEFAULT false;

-- sso_source_role is what the SIEM last asserted, e.g. 'L3:ro'. Pure provenance:
-- it answers "why does this person hold this role" without anybody having to
-- reconstruct the mapping from memory or go digging in the audit trail.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_source_role TEXT;

-- 'siem' joins the auth_provider vocabulary. It is deliberately its own value
-- rather than being folded into 'oidc': the SIEM is not an OIDC provider to
-- GuardRail, the linking column is different, and telling them apart is what
-- lets "change your password at your identity provider" name the right one.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_auth_provider_check;
ALTER TABLE users ADD CONSTRAINT users_auth_provider_check
    CHECK (auth_provider IN ('local', 'ldap', 'oidc', 'saml', 'siem'));

-- ---------------------------------------------------------------------------
-- auth_sessions
-- ---------------------------------------------------------------------------

-- sso marks a refresh-token family that was opened by a SIEM exchange rather
-- than by a password.
--
-- It exists for exactly one decision: whether the organization's source-address
-- policy applies to this session (GUARDRAIL_SSO_ALLOWLIST_BYPASS, off by
-- default). The marker has to live on the SESSION and not only in the access
-- token, because a refresh mints a new access token from the user record — so
-- without a column here the flag would evaporate at the first refresh and log an
-- off-network analyst out fifteen minutes into their shift, which is the kind of
-- bug that gets blamed on the network for a week.
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS sso BOOLEAN NOT NULL DEFAULT false;
