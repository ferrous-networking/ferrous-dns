CREATE INDEX IF NOT EXISTS idx_managed_domains_domain ON managed_domains(domain, enabled, action);
CREATE INDEX IF NOT EXISTS idx_query_log_retention ON query_log(created_at);
