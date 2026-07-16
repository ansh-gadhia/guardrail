-- Reverse 0008: restore the approval workflow schema (empty; historical approval
-- rows are not recoverable).

BEGIN;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE access_sessions ADD COLUMN IF NOT EXISTS approval_id UUID;
ALTER TABLE access_sessions DROP CONSTRAINT IF EXISTS access_sessions_status_check;
ALTER TABLE access_sessions
    ADD CONSTRAINT access_sessions_status_check
    CHECK (status IN ('pending', 'approved', 'active', 'ended', 'denied', 'expired'));

CREATE TABLE IF NOT EXISTS approval_requests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    access_session_id UUID NOT NULL REFERENCES access_sessions (id) ON DELETE CASCADE,
    requested_by      UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    approver_id       UUID REFERENCES users (id) ON DELETE SET NULL,
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','approved','denied','expired')),
    mode              TEXT NOT NULL DEFAULT 'window' CHECK (mode IN ('one_time','window')),
    valid_minutes     INT NOT NULL DEFAULT 60,
    reason            TEXT NOT NULL DEFAULT '',
    decided_at        TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_approvals_org_status ON approval_requests (organization_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON approval_requests TO guardrail_app;

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY approval_requests_isolation ON approval_requests
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

COMMIT;
