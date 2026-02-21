-- Performance migration: index improvements for 100k q/s workloads
--
-- Changes:
-- 1. Add (query_source, created_at DESC) index so range scans on created_at
--    can also filter out query_source = 'internal' at the index level.
-- 2. Rebuild idx_query_log_stats_coverage to include cache_refresh, enabling
--    index-only scans for the cache-stats aggregation query.
-- 3. Drop idx_query_log_domain and idx_query_log_record_type: both are fully
--    covered by the composite indexes added in phase4, so they only add write
--    overhead (2 extra index updates per INSERT) without benefiting any query.
-- 4. Add a composite index on managed_domains (group_id, enabled, action) to
--    avoid full-table scans when the admin API filters by group or status.
-- 5. Run ANALYZE on the two largest tables so the query planner uses accurate
--    cardinality statistics for the new indexes.

-- 1. New covering index: query_source + created_at
--    Queries like:
--      WHERE query_source = 'client' AND created_at >= datetime('now', '-24 hours')
--    can now skip 'internal' rows entirely inside the index.
CREATE INDEX IF NOT EXISTS idx_query_log_source_created
    ON query_log(query_source, created_at DESC);

-- 2. Rebuild stats-coverage index to include cache_refresh
--    The cache-stats query aggregates cache_hit, blocked, cache_refresh and
--    response_time_ms; with cache_refresh present the scan becomes index-only.
DROP INDEX IF EXISTS idx_query_log_stats_coverage;
CREATE INDEX idx_query_log_stats_coverage
    ON query_log(created_at DESC, cache_hit, blocked, response_time_ms, record_type, cache_refresh);

-- 3. Drop redundant single-column indexes
--    idx_query_log_domain      is covered by idx_query_log_domain_stats
--    idx_query_log_record_type is covered by idx_query_log_type_distribution
--    Removing them reduces INSERT overhead from 9 index updates to 7.
DROP INDEX IF EXISTS idx_query_log_domain;
DROP INDEX IF EXISTS idx_query_log_record_type;

-- 4. Index for managed_domains (previously had no indexes at all)
CREATE INDEX IF NOT EXISTS idx_managed_domains_group_enabled
    ON managed_domains(group_id, enabled, action);

-- 5. Refresh query-planner statistics for the two most queried tables
ANALYZE query_log;
ANALYZE clients;
