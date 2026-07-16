-- Persist the session's attribution text.
--
-- The watermark ("someone@example.com · 4f2a91c3") was built at Connect time and
-- handed to the gateway, but it was never stored. Every other read of a session
-- goes through the repository, which returned a Session with Watermark empty —
-- and Session.WatermarkOr() then fell back to "session <uuid>".
--
-- That fallback existed so an accountability control could not silently switch
-- itself off. It worked, and it hid this: the console asks GET /sessions/:id for
-- the text to draw over a desktop, so every desktop session was watermarked with
-- a bare session id while the web and SSH gateways — which stamp the string at
-- Establish time, from the in-memory Session that still had it — showed the
-- operator's email. Same control, two different answers, decided by whether the
-- Session had made a round trip through Postgres.
--
-- It is a column and not a derivation because it is a record of what was
-- actually displayed. Deriving it later from the user row would re-render a
-- watermark from today's email for a session watermarked last year, and the
-- whole point of the text is to join a screenshot back to this row.
ALTER TABLE access_sessions ADD COLUMN IF NOT EXISTS watermark TEXT;

COMMENT ON COLUMN access_sessions.watermark IS
    'Attribution text drawn over the session UI: the operator''s email and the short '
    'session id, as it was rendered at Connect time. NULL for sessions created before '
    'this column, which fall back to the session id.';
