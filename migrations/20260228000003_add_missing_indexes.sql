-- Hot-path lookup for managed domains (block filter)
CREATE INDEX IF NOT EXISTS idx_managed_domains_domain ON managed_domains(domain, enabled, action);

-- Retention job: query_log cleanup by created_at
CREATE INDEX IF NOT EXISTS idx_query_log_retention ON query_log(created_at);
