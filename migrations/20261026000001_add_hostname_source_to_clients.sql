-- Where a client's hostname came from: 'manual' when typed in through the
-- dashboard or the API, 'ptr' when the hostname sync set it. A manual name is
-- never replaced by the sync. NULL for rows written before this migration,
-- which the sync treats as its own. Only filtered on with last_seen, so no index.
ALTER TABLE clients ADD COLUMN hostname_source TEXT;
