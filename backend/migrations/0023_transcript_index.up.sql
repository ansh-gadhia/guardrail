-- 0023_transcript_index: give the transcript's index its own artifact kind.
--
-- Both recorders write a JSON index beside their payload, and both filed it
-- under kind 'metadata'. That was unambiguous only for as long as a recording
-- could contain one capture. A terminal device set to capture BOTH a transcript
-- and video produces two indexes on one recording, and the playback endpoint
-- fetches a manifest by kind — so the video player could be handed the
-- transcript's index, or the reverse, depending on which row came back first.
--
-- 'metadata' stays the screencast manifest, because that is what the existing
-- /recording/manifest endpoint serves and what every recorded web session
-- already has. The transcript's index moves to its own kind.
--
-- Recordings written before this keep their index under 'metadata'; the
-- transcript endpoint falls back to it, so old transcripts still replay.
ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata', 'transcript', 'desktop', 'transcript_index'));
