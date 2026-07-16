-- 0008_drop_approvals: the approval workflow has been removed. Brokered sessions
-- are established immediately (subject to resource-level entitlement, added in
-- 0009); there is no longer a pending/approved/denied lifecycle, no per-device
-- approval gate, and no approval_requests table.

BEGIN;

-- Collapse any in-flight approval states onto 'ended' before tightening the
-- status domain, so the new CHECK constraint can be added without violation.
ALTER TABLE access_sessions DROP CONSTRAINT IF EXISTS access_sessions_status_check;
UPDATE access_sessions SET status = 'ended'
    WHERE status IN ('pending', 'approved', 'denied');
ALTER TABLE access_sessions
    ADD CONSTRAINT access_sessions_status_check
    CHECK (status IN ('active', 'ended', 'expired'));

ALTER TABLE access_sessions DROP COLUMN IF EXISTS approval_id;

DROP TABLE IF EXISTS approval_requests;

ALTER TABLE devices DROP COLUMN IF EXISTS requires_approval;

-- Prune permissions that no route enforces: the approval:* pair (the workflow is
-- gone) and credential:read (device credentials are inline on the device, never a
-- separate read surface). The FK from role_permissions cascades, removing any
-- lingering grants.
DELETE FROM permissions WHERE key IN ('approval:read', 'approval:decide', 'credential:read');

COMMIT;
