ALTER TABLE query_log ADD COLUMN dnssec_status TEXT;
CREATE INDEX IF NOT EXISTS idx_query_log_dnssec_status ON query_log(dnssec_status);
