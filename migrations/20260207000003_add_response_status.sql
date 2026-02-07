-- Add response_status column to query_log table
-- This allows tracking DNS response codes: NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT, BLOCKED

-- SQLite doesn't support IF NOT EXISTS for ALTER TABLE, so we check in application
ALTER TABLE query_log ADD COLUMN response_status TEXT;

-- Add index for filtering by status
CREATE INDEX IF NOT EXISTS idx_query_log_response_status 
ON query_log(response_status);

-- Add index for error queries (helps with debugging)
CREATE INDEX IF NOT EXISTS idx_query_log_errors 
ON query_log(response_status) 
WHERE response_status != 'NOERROR';
