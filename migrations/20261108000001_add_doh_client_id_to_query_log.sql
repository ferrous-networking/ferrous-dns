-- The Client ID from a `/dns-query/<client_id>` DoH path. NULL for queries
-- sent to `/dns-query` or over any other DNS transport.
ALTER TABLE query_log ADD COLUMN doh_client_id TEXT;
