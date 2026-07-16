-- Terminal transcripts as a recording artifact kind.
--
-- recording_artifacts.kind was CHECK (kind IN ('video','screenshot','metadata')),
-- which is the vocabulary of a screen recorder. An SSH session has no frames: its
-- evidence is the text the device printed, which is both smaller and searchable.
-- Without this the transcript blob was written to storage and then rejected on
-- insert, leaving a finalized recording pointing at nothing.
ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata', 'transcript'));
