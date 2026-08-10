-- 0022_recording_kinds: what a recorded session captures, not just whether it is
-- recorded.
--
-- record_sessions answers "is this device recorded". It cannot answer "recorded
-- how", and for a terminal device that question has more than one right answer:
-- the transcript is small, searchable and exact, while a video shows the session
-- as the operator actually saw it — the pauses, the cursor, the screen a reviewer
-- would have been looking at. They are evidence of different kinds, and a shop
-- that wants both should not have to pick.
--
-- So record_sessions stays the master switch (and keeps governing who may turn
-- recording off — see CanSetRecording), and this column says what is captured
-- when it is on.
BEGIN;

ALTER TABLE devices ADD COLUMN recording_kinds TEXT[] NOT NULL DEFAULT '{}';

-- Backfill so every existing device keeps capturing exactly what it captures
-- today. An empty array on a recorded device would read as "record nothing",
-- which is the one outcome a migration of an audit control must never produce.
UPDATE devices SET recording_kinds =
    CASE
        WHEN NOT record_sessions          THEN '{}'::TEXT[]
        WHEN scheme IN ('ssh', 'telnet')  THEN ARRAY['transcript']
        WHEN scheme IN ('rdp', 'vnc')     THEN ARRAY['desktop']
        ELSE                                   ARRAY['video']
    END;

-- <@ is array containment: every element must be one of the known kinds. This
-- rejects a typo'd kind at write time rather than letting a device claim a
-- capture no gateway performs — the same failure 0016 and 0019 were written to
-- undo, where a recording was taken and then thrown away at the last insert.
ALTER TABLE devices ADD CONSTRAINT devices_recording_kinds_check
    CHECK (recording_kinds <@ ARRAY['transcript', 'video', 'desktop']::TEXT[]);

COMMIT;
