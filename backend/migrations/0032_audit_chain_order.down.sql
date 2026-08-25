DROP INDEX IF EXISTS ix_audit_seq;
ALTER TABLE audit_events
    DROP COLUMN IF EXISTS hash_version,
    DROP COLUMN IF EXISTS seq;
