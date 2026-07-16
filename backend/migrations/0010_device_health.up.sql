-- 0010_device_health: device liveness. A background poller probes each device's
-- management endpoint and records whether it is reachable, so the console can
-- show online/offline rather than implying every registered device is up.

BEGIN;

-- Health lives in its own table rather than on devices: writing liveness onto
-- devices would fire trg_devices_updated on every poll, churning updated_at and
-- making an automated probe look like an operator edit in the audit trail.
CREATE TABLE device_health (
    device_id            UUID PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    status               TEXT NOT NULL DEFAULT 'unknown'
                             CHECK (status IN ('online', 'offline', 'unknown')),
    checked_at           TIMESTAMPTZ,
    latency_ms           INT,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_error           TEXT
);

-- Grant-only, no RLS: keyed on device_id, and RLS on devices gates every
-- device_id a tenant can reach on read. Writes come only from the system-scoped
-- poller, which is cross-tenant by design (it probes every org's devices).
GRANT SELECT, INSERT, UPDATE, DELETE ON device_health TO guardrail_app;

COMMIT;
