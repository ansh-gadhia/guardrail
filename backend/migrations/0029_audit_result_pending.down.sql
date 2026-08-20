-- Rolling back fails while any 'pending' event exists, because the constraint is
-- validated against the existing rows. That is correct: the alternative is
-- rewriting or deleting audit events to make a schema change succeed, which is
-- precisely what the append-only hash chain exists to prevent.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_result_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_result_check
    CHECK (result IN ('success', 'failure', 'denied'));
