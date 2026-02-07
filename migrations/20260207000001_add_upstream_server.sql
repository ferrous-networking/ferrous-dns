-- Add upstream_server column to query_log table
ALTER TABLE query_log ADD COLUMN upstream_server TEXT;

-- Add index for faster queries filtering by upstream server
CREATE INDEX IF NOT EXISTS idx_query_log_upstream_server ON query_log(upstream_server);
