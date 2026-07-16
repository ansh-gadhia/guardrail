-- Transcript artifacts would violate the narrowed constraint. Refuse rather than
-- delete: dropping them destroys the only record of what was typed on a device.
DO $$
DECLARE n INT;
BEGIN
    SELECT count(*) INTO n FROM recording_artifacts WHERE kind = 'transcript';
    IF n > 0 THEN
        RAISE EXCEPTION 'cannot revert: % transcript artifact(s) exist. Export or delete them first.', n;
    END IF;
END $$;

ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata'));
