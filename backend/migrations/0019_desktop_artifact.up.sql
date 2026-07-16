-- A desktop recording artifact kind.
--
-- The guacd gateway stores each RDP/VNC recording as a Guacamole protocol dump
-- and registers it with kind 'desktop'. The constraint did not list that value,
-- so every desktop recording was captured by guacd, read back, uploaded to the
-- blob store, and then REJECTED at the final insert:
--
--   new row for relation "recording_artifacts" violates check constraint
--   "recording_artifacts_kind_check" (SQLSTATE 23514)
--
-- The session recorded and the evidence was thrown away at the last step. It is
-- logged, but a log line is not a recording — and this is precisely the failure
-- the product exists to prevent, so it is worth naming plainly.
--
-- 'desktop' rather than reusing 'video': the payload is not frames, it is an
-- instruction stream the player replays. Calling it video would make a download
-- endpoint hand out a .guac file that no video player can open.
--
-- 0016 did exactly this for 'transcript' when the SSH gateway landed; this is the
-- same step for the desktop gateway.
ALTER TABLE recording_artifacts DROP CONSTRAINT IF EXISTS recording_artifacts_kind_check;
ALTER TABLE recording_artifacts ADD CONSTRAINT recording_artifacts_kind_check
    CHECK (kind IN ('video', 'screenshot', 'metadata', 'transcript', 'desktop'));
