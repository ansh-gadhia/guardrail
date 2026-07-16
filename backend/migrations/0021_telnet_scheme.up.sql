-- Telnet, at the storage layer.
--
-- The telnet gateway, the protocol vocabulary in both bounded contexts, the
-- vault's injection rule and the console's picker all landed without this, and
-- 0014's CHECK still listed only the five protocols that existed then. The set is
-- deliberately closed and enforced in the database, so all of that application
-- code was unreachable: registering a telnet device failed at the INSERT with a
-- constraint violation, and no amount of Go could have made it work.
--
-- This is the step 0014's own comment asks for — "adding a protocol here is
-- deliberately a schema change" — performed late.
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_scheme_check;
ALTER TABLE devices ADD CONSTRAINT devices_scheme_check
    CHECK (scheme IN ('http', 'https', 'ssh', 'rdp', 'vnc', 'telnet'));
