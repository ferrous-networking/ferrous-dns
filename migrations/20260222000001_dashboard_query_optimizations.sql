-- ============================================================================
-- Dashboard Query Optimizations
-- ============================================================================
-- Problem 1: idx_query_log_stats_coverage lacks query_source, block_source and
--   client_ip, forcing a heap lookup for every row in get_stats().
--   COUNT(DISTINCT client_ip) is especially costly without those columns.
--
-- Problem 2: get_cache_stats() filters only on created_at; after rebuilding
--   stats_coverage to lead with query_source, it would lose its covering index.
--
-- Problem 3: idx_query_log_type_distribution lacks query_source as a leading
--   key, so the planner cannot skip non-client rows early.
--
-- Problem 4: clients.get_stats() does a full heap scan; a covering index on
--   last_seen + mac_address + hostname eliminates all table lookups.
-- ============================================================================

-- 1. Rebuild idx_query_log_stats_coverage
--    Old: (created_at DESC, cache_hit, blocked, response_time_ms, record_type, cache_refresh)
--    New: leads with query_source so the planner can skip non-client rows at
--         the index level; includes block_source and client_ip so get_stats()
--         becomes a true index-only scan (no heap access per row).
--    Partial: WHERE response_time_ms IS NOT NULL mirrors the stats query's own
--             filter, reducing index size and improving cache efficiency.
DROP INDEX IF EXISTS idx_query_log_stats_coverage;
CREATE INDEX idx_query_log_stats_coverage
    ON query_log(query_source, created_at DESC, blocked, cache_hit,
                 response_time_ms, cache_refresh, block_source, client_ip)
    WHERE response_time_ms IS NOT NULL;

-- 2. New covering index for get_cache_stats()
--    That query filters only on created_at (no query_source in WHERE) so it
--    cannot use the new stats_coverage index above.  This dedicated index with
--    created_at as the leading key keeps it as a covering/index-only scan.
CREATE INDEX IF NOT EXISTS idx_query_log_cache_stats
    ON query_log(created_at DESC, cache_hit, cache_refresh, blocked, query_source);

-- 3. Rebuild idx_query_log_type_distribution
--    Old: (record_type, created_at DESC, blocked, cache_hit)
--    New: query_source as the leading key lets the planner use it for the
--         WHERE query_source = 'client' filter before the created_at range
--         scan, and record_type is read directly from the index for GROUP BY.
DROP INDEX IF EXISTS idx_query_log_type_distribution;
CREATE INDEX idx_query_log_type_distribution
    ON query_log(query_source, created_at DESC, record_type);

-- 4. Covering index for clients.get_stats()
--    Enables an index-only scan: last_seen for the CASE time comparisons,
--    mac_address and hostname for the IS NOT NULL checks — no heap access.
CREATE INDEX IF NOT EXISTS idx_clients_stats_coverage
    ON clients(last_seen DESC, mac_address, hostname);

-- 5. Refresh query-planner statistics for both optimised tables
ANALYZE query_log;
ANALYZE clients;
