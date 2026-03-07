CREATE INDEX IF NOT EXISTS idx_query_log_stats_coverage 
ON query_log(created_at DESC, cache_hit, blocked, response_time_ms, record_type);

CREATE INDEX IF NOT EXISTS idx_query_log_date_status 
ON query_log(created_at DESC, response_status)
WHERE response_status IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_query_log_performance 
ON query_log(cache_hit, created_at DESC, response_time_ms, upstream_server)
WHERE response_time_ms IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_query_log_client_timeline 
ON query_log(client_ip, created_at DESC, domain, record_type, blocked, response_status);

CREATE INDEX IF NOT EXISTS idx_query_log_domain_stats 
ON query_log(domain, created_at DESC, response_time_ms, cache_hit, blocked);

CREATE INDEX IF NOT EXISTS idx_query_log_type_distribution 
ON query_log(record_type, created_at DESC, blocked, cache_hit);
