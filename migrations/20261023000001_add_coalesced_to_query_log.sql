-- A query's part in coalescing: identical queries in flight at the same time
-- share one upstream request. 'leader' for the query whose answer was shared,
-- 'follower' for one that joined it, NULL otherwise and for rows written
-- before this migration. Only displayed, never filtered on: no index.
ALTER TABLE query_log ADD COLUMN coalesced TEXT;
