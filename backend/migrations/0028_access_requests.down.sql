-- Reverse 0028_access_requests.

BEGIN;

DROP TABLE IF EXISTS device_access_grants;
DROP TABLE IF EXISTS access_request_decisions;
DROP TABLE IF EXISTS access_requests;

ALTER TABLE devices DROP COLUMN IF EXISTS min_approvals;
ALTER TABLE devices DROP COLUMN IF EXISTS requires_approval;

COMMIT;
