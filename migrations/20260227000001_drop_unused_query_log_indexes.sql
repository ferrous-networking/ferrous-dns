DROP INDEX IF EXISTS idx_query_log_created_at;
DROP INDEX IF EXISTS idx_query_log_cache_refresh;
DROP INDEX IF EXISTS idx_query_log_dnssec_status;
DROP INDEX IF EXISTS idx_query_log_upstream_server;
DROP INDEX IF EXISTS idx_query_log_response_status;
DROP INDEX IF EXISTS idx_query_log_errors;
DROP INDEX IF EXISTS idx_query_log_date_status;
DROP INDEX IF EXISTS idx_query_log_performance;
DROP INDEX IF EXISTS idx_query_log_client_timeline;
DROP INDEX IF EXISTS idx_query_log_domain_stats;
DROP INDEX IF EXISTS idx_query_log_group;
DROP INDEX IF EXISTS idx_query_log_type_distribution;
DROP INDEX IF EXISTS idx_query_log_source_created;
CREATE INDEX idx_query_log_source_created
    ON query_log(query_source, created_at DESC, blocked, record_type);

ANALYZE query_log;
