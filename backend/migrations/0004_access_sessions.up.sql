-- 0004_access_sessions: brokered access sessions, approval requests, session
-- recordings, and the per-session event timeline used for playback and audit.

BEGIN;

CREATE TABLE access_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    device_id       UUID NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    protocol        TEXT NOT NULL DEFAULT 'https',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('pending','approved','active','ended','denied','expired')),
    approval_id     UUID,
    granted_from    TIMESTAMPTZ,
    granted_until   TIMESTAMPTZ,
    client_ip       INET,
    user_agent      TEXT,
    gateway_node    TEXT,
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    end_reason      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_sessions_org_status ON access_sessions (organization_id, status);
CREATE INDEX ix_sessions_user ON access_sessions (user_id, created_at DESC);
CREATE INDEX ix_sessions_device ON access_sessions (device_id, created_at DESC);

CREATE TABLE approval_requests (
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
CREATE INDEX ix_approvals_org_status ON approval_requests (organization_id, status);

CREATE TABLE recordings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    access_session_id UUID NOT NULL REFERENCES access_sessions (id) ON DELETE CASCADE,
    status            TEXT NOT NULL DEFAULT 'recording'
                      CHECK (status IN ('recording','finalized','failed')),
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at          TIMESTAMPTZ,
    duration_ms       BIGINT,
    retention_until   TIMESTAMPTZ,
    storage_bucket    TEXT NOT NULL DEFAULT '',
    storage_prefix    TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_recordings_session ON recordings (access_session_id);

CREATE TABLE recording_artifacts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recording_id UUID NOT NULL REFERENCES recordings (id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('video','screenshot','metadata')),
    object_key   TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL DEFAULT 0,
    content_type TEXT NOT NULL DEFAULT '',
    checksum     TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE session_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_session_id UUID NOT NULL REFERENCES access_sessions (id) ON DELETE CASCADE,
    ts                TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind              TEXT NOT NULL,   -- url_change | click | key | nav | resize
    data              JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ix_session_events ON session_events (access_session_id, ts);

-- Grants + RLS.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    access_sessions, approval_requests, recordings, recording_artifacts, session_events
    TO guardrail_app;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['access_sessions','approval_requests','recordings'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$CREATE POLICY %1$s_isolation ON %1$s
            USING (app_is_super_admin() OR organization_id = app_current_org())
            WITH CHECK (app_is_super_admin() OR organization_id = app_current_org())$f$, t);
    END LOOP;
END $$;

COMMIT;
