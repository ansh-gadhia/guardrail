ALTER TABLE org_settings
    DROP COLUMN IF EXISTS ip_blocklist,
    DROP COLUMN IF EXISTS ip_blocklist_enabled,
    DROP COLUMN IF EXISTS ip_allowlist,
    DROP COLUMN IF EXISTS ip_allowlist_enabled,
    DROP COLUMN IF EXISTS branding_enabled,
    DROP COLUMN IF EXISTS client_logo,
    DROP COLUMN IF EXISTS client_name;
