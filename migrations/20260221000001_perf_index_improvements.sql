CREATE INDEX IF NOT EXISTS idx_query_log_source_created
    ON query_log(query_source, created_at DESC);
DROP INDEX IF EXISTS idx_query_log_stats_coverage;
CREATE INDEX idx_query_log_stats_coverage
    ON query_log(created_at DESC, cache_hit, blocked, response_time_ms, record_type, cache_refresh);
DROP INDEX IF EXISTS idx_query_log_domain;
DROP INDEX IF EXISTS idx_query_log_record_type;
CREATE INDEX IF NOT EXISTS idx_managed_domains_group_enabled
    ON managed_domains(group_id, enabled, action);
ANALYZE query_log;
ANALYZE clients;
