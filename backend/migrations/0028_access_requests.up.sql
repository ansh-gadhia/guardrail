-- 0028_access_requests: the approval gate.
--
-- Approvals existed once and were removed in 0008, which replaced them with
-- role-based device entitlement in 0009. This is a rebuild, not a revival, and
-- it differs from the removed design in one structural way: a decision to allow
-- somebody permanently is not a decision, it is a grant. It gets its own table,
-- with a list and a revoke path, because access that only ever accumulates and
-- can never be enumerated is how a PAM deployment rots.
--
-- Pending requests deliberately do NOT go back into access_sessions.status.
-- 0008 tightened that column to ('active','ended','expired') and it was right:
-- that table means "a thing that reached a device". Pending rows there would
-- pollute session listings, active counts, statistics, the reaper and the
-- recording model, every one of which assumes a session is live or was.

BEGIN;

-- ---------------------------------------------------------------------------
-- Device policy.
-- ---------------------------------------------------------------------------
-- Same column 0005 added and 0008 dropped, same default: off, so every existing
-- device is unaffected by this migration.
ALTER TABLE devices ADD COLUMN requires_approval BOOLEAN NOT NULL DEFAULT false;

-- The two-person rule. One approval is right for a lab switch and wrong for a
-- core firewall, and that is a property of the device, not of the organization.
ALTER TABLE devices ADD COLUMN min_approvals INT NOT NULL DEFAULT 1
    CHECK (min_approvals BETWEEN 1 AND 5);

-- ---------------------------------------------------------------------------
-- Requests.
-- ---------------------------------------------------------------------------
CREATE TABLE access_requests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    user_id           UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id         UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','approved','denied','expired','cancelled')),
    -- Required, not optional. Without it the approver decides blind, and it
    -- turns out to be the most useful field in the record six months later.
    reason            TEXT NOT NULL,
    -- What the requester asked for, and what they got. The approver may shorten
    -- but never silently lengthen.
    requested_minutes INT NOT NULL CHECK (requested_minutes BETWEEN 1 AND 1440),
    granted_minutes   INT CHECK (granted_minutes BETWEEN 1 AND 1440),
    -- Which button the approver pressed. NULL until decided.
    grant_scope       TEXT CHECK (grant_scope IN ('once','always')),
    -- Snapshotted from the device at request time: raising a device's bar must
    -- not retroactively invalidate a decision already being made.
    min_approvals     INT NOT NULL DEFAULT 1 CHECK (min_approvals BETWEEN 1 AND 5),
    -- The requester's effective rank, snapshotted for the same reason: an
    -- approver must outrank the request as it was made.
    requester_level   INT NOT NULL DEFAULT 0,
    -- Emergency access is granted first and reviewed afterwards. See the
    -- reviewed_* columns; an unreviewed emergency is an open item, not history.
    is_emergency      BOOLEAN NOT NULL DEFAULT false,
    reviewed_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    reviewed_at       TIMESTAMPTZ,
    review_note       TEXT NOT NULL DEFAULT '',
    -- The rank this request has climbed to after going unanswered.
    escalated_level   INT,
    -- Backfilled when an approved request is redeemed. This is the join that
    -- lets an auditor start from a recording and ask who let this happen.
    session_id        UUID REFERENCES access_sessions (id) ON DELETE SET NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_requests_org ON access_requests (organization_id, created_at DESC);
CREATE INDEX ix_requests_user ON access_requests (user_id, created_at DESC);
-- The reaper's query: everything still pending that has run out of time.
CREATE INDEX ix_requests_pending ON access_requests (expires_at)
    WHERE status = 'pending';
-- The emergency review queue.
CREATE INDEX ix_requests_unreviewed ON access_requests (organization_id, created_at DESC)
    WHERE is_emergency AND reviewed_at IS NULL;

CREATE TRIGGER trg_requests_updated BEFORE UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Decisions.
-- ---------------------------------------------------------------------------
-- Separate from the request because the two-person rule has to count them, and
-- because a composite primary key on (request_id, decided_by) makes "the same
-- person approved twice" impossible in the database rather than in a code path
-- somebody can forget to write.
CREATE TABLE access_request_decisions (
    request_id UUID NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
    decided_by UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    decision   TEXT NOT NULL CHECK (decision IN ('approve','deny')),
    note       TEXT NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, decided_by)
);

-- ---------------------------------------------------------------------------
-- Standing grants — the "allow all time" button.
-- ---------------------------------------------------------------------------
CREATE TABLE device_access_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    granted_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    request_id      UUID REFERENCES access_requests (id) ON DELETE SET NULL,
    -- NULL means "all time". The column exists even though no button sets it,
    -- because "allow until Friday" is what people reach for once they have
    -- lived with this — and it should be a UI change, not a migration.
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_grants_org ON device_access_grants (organization_id, created_at DESC);
-- The gate's lookup, and the reason a revoked grant stops mattering instantly.
CREATE UNIQUE INDEX uq_grant_live ON device_access_grants (user_id, device_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Isolation.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
    access_requests, access_request_decisions, device_access_grants
    TO guardrail_app;

ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY requests_isolation ON access_requests
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

ALTER TABLE device_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY grants_isolation ON device_access_grants
    USING (app_is_super_admin() OR organization_id = app_current_org())
    WITH CHECK (app_is_super_admin() OR organization_id = app_current_org());

-- access_request_decisions carries no organization_id of its own: it is keyed on
-- request_id, and RLS on access_requests gates every request_id a tenant can
-- reach. This mirrors device_group_members from 0003 and the role join tables
-- from 0009. Writers must source request ids through the RLS-protected parent.

COMMIT;
