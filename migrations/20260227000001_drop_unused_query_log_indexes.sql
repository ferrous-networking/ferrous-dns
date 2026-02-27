-- Drop 11 indexes not used by any query in the codebase
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

-- Merge idx_query_log_type_distribution into source_created
-- Old source_created: (query_source, created_at DESC, blocked)
-- Old type_distribution: (query_source, created_at DESC, record_type)
-- New: combines both + serves count, timeline, recent, and record type distribution
DROP INDEX IF EXISTS idx_query_log_type_distribution;
DROP INDEX IF EXISTS idx_query_log_source_created;
CREATE INDEX idx_query_log_source_created
    ON query_log(query_source, created_at DESC, blocked, record_type);

ANALYZE query_log;
