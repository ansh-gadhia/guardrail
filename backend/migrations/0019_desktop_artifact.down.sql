-- Revert to the pre-desktop artifact kinds.
--
-- Refuses rather than deletes: a 'desktop' artifact row is the only pointer to a
-- stored recording, and dropping it would orphan the blob while leaving the
-- recording looking intact. Mirrors 0016's reasoning for 'transcript'.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM recording_artifacts WHERE kind = 'desktop';
    IF n > 0 THEN
        RAISE EXCEPTION 'refusing to roll back: % desktop recording artifact(s) exist. '
            'Removing the constraint value would orphan their stored blobs.', n;
    END IF;
END $$;

ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata', 'transcript'));
