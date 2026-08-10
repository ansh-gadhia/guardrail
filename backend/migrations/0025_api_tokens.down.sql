-- Dropping the table revokes every machine credential at once: the hashes are
-- the only copy, so nothing can be restored by re-creating it.
BEGIN;

DROP POLICY IF EXISTS api_tokens_isolation ON api_tokens;
DROP TABLE IF EXISTS api_tokens;

COMMIT;
