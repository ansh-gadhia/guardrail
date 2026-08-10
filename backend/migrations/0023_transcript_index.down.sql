-- Fold transcript indexes back under 'metadata' before narrowing the constraint,
-- or the rows this migration created would violate it and the down would fail
-- halfway. A recording holding both captures ends up with two 'metadata' rows —
-- the ambiguity 0023 exists to remove — which is the honest cost of reverting.
BEGIN;

UPDATE recording_artifacts SET kind = 'metadata' WHERE kind = 'transcript_index';

ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata', 'transcript', 'desktop'));

COMMIT;
