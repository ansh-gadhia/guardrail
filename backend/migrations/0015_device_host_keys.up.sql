-- Pinned SSH host keys (trust-on-first-use).
--
-- This is the SSH analogue of verify_tls on a web device. Without it, anything
-- that answers on port 22 is handed the vaulted credential and its session is
-- recorded as though it were the device.
--
-- A separate table rather than a column on devices: writing here would otherwise
-- fire trg_devices_updated and churn updated_at on every connect, and the same
-- reasoning already put device_health in its own table.
CREATE TABLE device_host_keys (
    device_id   UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    -- The key in authorized_keys form, exactly as presented by the device.
    host_key    TEXT NOT NULL,
    -- Which session first saw it, so an unexpected change can be traced back to
    -- the connect that pinned the original.
    pinned_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No RLS policy, and that is deliberate: a host key is not tenant data. It is a
-- fact about a machine on the network, and the device_id foreign key already
-- confines every row to a device whose own RLS governs who can see it. Adding a
-- policy here would need an organization_id copied from devices — a second
-- source of truth for the same fact, and a way for the two to disagree.
GRANT SELECT, INSERT, UPDATE, DELETE ON device_host_keys TO guardrail_app;
