-- A fourth audit outcome: pending.
--
-- Raising an access request was recorded as 'denied', because 'denied' was the
-- closest of the three values to "the connect did not proceed". It is not close
-- enough: the Audit Log and the dashboard's activity feed both showed
-- "approval.requested — denied" directly above the "approval.granted — success"
-- for the same request_id, so the log contradicted itself about access that had
-- in fact been approved seconds later. Nothing can correct those rows after the
-- fact — the chain is append-only and the result is inside the hash — so the
-- only fix is to stop writing the wrong value.
--
-- Like 0014's protocol set, this CHECK is deliberately closed: the vocabulary of
-- audit outcomes is a schema decision, not something application code may widen
-- on its own.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_result_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_result_check
    CHECK (result IN ('success', 'failure', 'denied', 'pending'));
