-- Revert to the pre-desktop injection methods.
--
-- A credential still using 'password' would violate the narrowed constraint. It
-- cannot be rewritten to another method — none of them can authenticate RDP or
-- VNC — and deleting it would silently strip the credential from a device that
-- looks configured. So refuse loudly and let an operator decide, exactly as 0014
-- does for the SSH methods.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM credentials WHERE injection = 'password' AND deleted_at IS NULL;
    IF n > 0 THEN
        RAISE EXCEPTION 'refusing to roll back: % credential(s) use the desktop ''password'' injection method. '
            'Remove or re-bind them first — no remaining method can authenticate RDP or VNC.', n;
    END IF;
END $$;

ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_injection_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_injection_check
    CHECK (injection IN ('form', 'basic', 'header', 'none', 'ssh-password', 'ssh-key'));
