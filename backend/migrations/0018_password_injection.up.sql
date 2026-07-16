-- A desktop credential injection method.
--
-- RDP and VNC authenticate with a username and password handed to guacd in its
-- connect handshake. None of the existing methods describe that: 'basic' is an
-- HTTP Authorization header, 'form' types into a web page, and 'ssh-password' is
-- named for the protocol it belongs to. Without a value that fits, a desktop
-- device could only be given a method that cannot authenticate it.
--
-- 0014 added the SSH methods when the SSH gateway landed; this is the same step
-- for the desktop gateway.
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_injection_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_injection_check
    CHECK (injection IN ('form', 'basic', 'header', 'none', 'ssh-password', 'ssh-key', 'password'));

COMMENT ON COLUMN credentials.injection IS
    'How the secret is presented to the device. Web: form | basic | header. '
    'Terminal: ssh-password | ssh-key. Desktop (RDP/VNC): password. none = no secret. '
    'The method must suit the device''s protocol — the API refuses a mismatch, because '
    'a credential that cannot authenticate looks configured and fails at Connect.';
