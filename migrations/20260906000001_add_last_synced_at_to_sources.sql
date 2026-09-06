-- RFC 3339 UTC timestamp of the last time this source's URL was fetched
-- successfully. NULL means never successfully fetched: a source that has no
-- URL, one added before this migration, or one whose every fetch has failed.
-- A fetch failure deliberately leaves the previous value untouched, so a stamp
-- that stops advancing is the signal that a list has gone stale.
-- Only ever read back per row alongside the rest of the source, so no index.
ALTER TABLE blocklist_sources ADD COLUMN last_synced_at TEXT;
ALTER TABLE whitelist_sources ADD COLUMN last_synced_at TEXT;
