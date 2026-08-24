-- Transport protocol the client used to reach the resolver: 'udp', 'tcp',
-- 'dot', 'doh' or 'doq'. NULL for internally generated queries (cache
-- maintenance, DNSSEC validation) and for rows written before this migration.
-- Filtered on with a static equality fragment, but the query log is always
-- range-scanned by created_at first, so no separate index.
ALTER TABLE query_log ADD COLUMN protocol TEXT;
