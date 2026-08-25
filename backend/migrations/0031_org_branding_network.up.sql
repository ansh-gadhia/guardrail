-- Two more per-organization policies: how the console is branded, and which
-- source addresses may reach it.
--
-- BRANDING. A deployment sold to a client is that client's console, not the
-- vendor's. The rail under the product wordmark carried "Engineered by Virtual
-- Galaxy" as a hard-coded seal, so putting a customer's own name on it meant a
-- rebuild. These three columns make it a setting; when they are empty the
-- console falls back to exactly what it showed before, so an install that never
-- touches this looks unchanged.
--
-- The logo is a data URI rather than a blob-store object on purpose. It is one
-- small image read on every page load by every signed-in user, and giving it its
-- own storage key, its own fetch and its own cache invalidation buys nothing:
-- inline it travels with the settings the shell already reads. The CHECK bounds
-- it so a 4 MB PNG cannot be pasted into a row that is on the hot path.
ALTER TABLE org_settings
    ADD COLUMN client_name TEXT NOT NULL DEFAULT ''
        CHECK (length(client_name) <= 120),
    ADD COLUMN client_logo TEXT NOT NULL DEFAULT ''
        CHECK (client_logo = '' OR (client_logo LIKE 'data:image/%' AND length(client_logo) <= 400000)),
    -- Branding is deliberately separate from "is it configured": an administrator
    -- who has uploaded a logo may still want the vendor seal back for a week
    -- without throwing the artwork away.
    ADD COLUMN branding_enabled BOOLEAN NOT NULL DEFAULT TRUE;

-- NETWORK POLICY. Two independent lists, each with its own switch, because they
-- answer different questions and are turned on at different times: an allowlist
-- says "only from here", a blocklist says "never from there". Coupling them to
-- one flag would mean an administrator who wants to bar one address has to first
-- enumerate every address that is allowed.
--
-- Entries are held as JSONB arrays of {cidr, note} rather than as a child table.
-- The whole policy is read together on every request and written as one document
-- by one form; a child table would add a join to the hot path and a second
-- transaction to the write, for a list that is measured in tens of rows.
ALTER TABLE org_settings
    ADD COLUMN ip_allowlist_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN ip_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(ip_allowlist) = 'array' AND jsonb_array_length(ip_allowlist) <= 256),
    ADD COLUMN ip_blocklist_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN ip_blocklist JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(ip_blocklist) = 'array' AND jsonb_array_length(ip_blocklist) <= 256);
