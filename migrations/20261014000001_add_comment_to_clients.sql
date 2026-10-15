-- A comment on a client, set through the Pi-hole compatible API (FTL keeps
-- one per client). NULL is no comment. Only read back with its row, so no index.
ALTER TABLE clients ADD COLUMN comment TEXT;
