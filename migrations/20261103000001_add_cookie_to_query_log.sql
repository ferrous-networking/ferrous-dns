-- What a query's DNS Cookie (RFC 7873) showed: 'client' for a client cookie
-- alone, 'valid' for a server cookie this server issued to the client in the
-- current or previous rotation window, 'invalid' for any other server cookie.
-- NULL when the query carried none, and for rows written before this
-- migration. Filtered on rarely and only within a page window: no index.
ALTER TABLE query_log ADD COLUMN cookie TEXT;
