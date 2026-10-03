-- Who ended a session.
--
-- A session ended from the console was recorded as end_reason 'admin_terminate'
-- whoever ended it: the operator pressing End session on their own work, the
-- page closing the session as its tab closed, and a supervisor cutting someone
-- else off all read the same, and none of them said who. The person was in the
-- audit trail all along; the session record, which is what the console shows
-- beside the recording, never had them.
ALTER TABLE access_sessions ADD COLUMN IF NOT EXISTS ended_by UUID;

-- Sessions that ended before this column existed get theirs from the audit
-- trail: the person on the last successful session.end recorded against the
-- session. The housekeeping ends (idle, window expiry) have no person behind
-- them and stay empty, which is the truth.
UPDATE access_sessions s
SET ended_by = e.actor_id
FROM (
    SELECT DISTINCT ON (session_id) session_id, actor_id
    FROM audit_events
    WHERE action = 'session.end'
      AND result = 'success'
      AND actor_id IS NOT NULL
      AND session_id IS NOT NULL
    ORDER BY session_id, ts DESC
) e
WHERE s.id = e.session_id
  AND s.ended_by IS NULL
  AND s.status IN ('ended', 'expired');
