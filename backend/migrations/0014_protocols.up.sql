-- Brokered protocols beyond the web.
--
-- devices.scheme was CHECK (scheme IN ('http','https')) — the column names the
-- protocol the device is reached over, and it rejected ssh/rdp/vnc at the
-- storage layer, so no amount of application code could have added one.
--
-- The set stays closed rather than becoming free text: the broker routes on this
-- value, and an unrecognised protocol must be impossible to store, not merely
-- unhandled. Adding a protocol here is deliberately a schema change.
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_scheme_check;
ALTER TABLE devices ADD CONSTRAINT devices_scheme_check
    CHECK (scheme IN ('http', 'https', 'ssh', 'rdp', 'vnc'));

-- Credential injection for non-HTTP protocols.
--
-- The existing methods are all HTTP-shaped: 'form' fills a login page, 'basic'
-- and 'header' set request headers. None describes handing a password or a
-- private key to an SSH transport handshake, so SSH credentials had no way to be
-- represented at all.
--
--   ssh-password: username + password authenticate the SSH connection
--   ssh-key:      the secret is a PEM private key; username is the login
--
-- Both are injected server-side by the gateway, exactly like the HTTP methods —
-- the operator never receives the secret.
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_injection_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_injection_check
    CHECK (injection IN ('form', 'basic', 'header', 'none', 'ssh-password', 'ssh-key'));
