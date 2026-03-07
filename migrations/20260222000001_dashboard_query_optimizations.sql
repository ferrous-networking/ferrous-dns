DROP INDEX IF EXISTS idx_query_log_stats_coverage;
CREATE INDEX idx_query_log_stats_coverage
    ON query_log(query_source, created_at DESC, blocked, cache_hit,
                 response_time_ms, cache_refresh, block_source, client_ip)
    WHERE response_time_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_query_log_cache_stats
    ON query_log(created_at DESC, cache_hit, cache_refresh, blocked, query_source);
DROP INDEX IF EXISTS idx_query_log_type_distribution;
CREATE INDEX idx_query_log_type_distribution
    ON query_log(query_source, created_at DESC, record_type);
CREATE INDEX IF NOT EXISTS idx_clients_stats_coverage
    ON clients(last_seen DESC, mac_address, hostname);
ANALYZE query_log;
ANALYZE clients;
