-- 0036_credential_aad: bind each sealed secret to the credential it belongs to.
--
-- WHY THIS EXISTS
--
-- AES-GCM takes an optional "additional authenticated data" argument: bytes that
-- are not encrypted but are covered by the authentication tag, so decryption
-- fails unless the opener supplies exactly the same ones. GuardRail passed nil.
--
-- Every credential in a deployment is sealed under the same KEK, so with no AAD
-- the five stored columns (secret_ciphertext, secret_nonce, dek_wrapped,
-- dek_nonce, kek_id) are self-contained AND self-authenticating: copy them from
-- the domain admin's row onto a credential you are allowed to resolve, and they
-- open cleanly. The gateway then injects a secret you were never entitled to,
-- and the audit trail records the account name from the row you named — so it
-- reports the wrong account for a use that really happened.
--
-- 0035 closed the sibling hole (repointing a BINDING at another credential).
-- This closes transplanting the CIPHERTEXT itself. Both were needed: they are
-- two ways to reach the same secret.
--
-- WHY A VERSION COLUMN RATHER THAN A FLAG DAY
--
-- Existing ciphertext was sealed with no AAD and cannot be opened as though it
-- had one. aad_version records which rule a row was sealed under:
--
--   0  sealed before this migration; opened with no AAD
--   1  bound to "guardrail/cred/v1|<organization_id>|<credential_id>"
--
-- The API re-seals every version-0 row at startup (ReSealLegacyCredentials) and
-- only then refuses version 0 outright. Until that runs, a version-0 row still
-- opens — which is the whole point: a security upgrade that takes the estate
-- offline gets rolled back rather than kept.
--
-- WHY DOWNGRADING DOES NOT WORK
--
-- Setting aad_version back to 0 on a version-1 row does not disarm the check: it
-- makes the opener pass no AAD, and the tag was computed over one, so
-- authentication fails and the row becomes unreadable rather than transplantable.

BEGIN;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS aad_version SMALLINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN credentials.aad_version IS
    '0 = sealed with no associated data (pre-0036); 1 = bound to organization_id and id. The API re-seals 0 to 1 at startup.';

-- The re-seal job asks "which rows are still version 0" on every boot.
CREATE INDEX IF NOT EXISTS ix_credentials_legacy_aad
    ON credentials (id) WHERE aad_version = 0 AND deleted_at IS NULL;

COMMIT;
