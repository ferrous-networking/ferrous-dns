-- Add dnssec_status column to query_log table
ALTER TABLE query_log ADD COLUMN dnssec_status TEXT;

-- Index for filtering by DNSSEC status
CREATE INDEX IF NOT EXISTS idx_query_log_dnssec_status ON query_log(dnssec_status);
