-- Rolling back strands any telnet device already registered: the constraint is
-- validated against existing rows, so this fails until they are removed. That is
-- correct — silently deleting a device to make a schema change succeed would be
-- worse than refusing.
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_scheme_check;
ALTER TABLE devices ADD CONSTRAINT devices_scheme_check
    CHECK (scheme IN ('http', 'https', 'ssh', 'rdp', 'vnc'));
