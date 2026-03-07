ALTER TABLE query_log ADD COLUMN response_status TEXT;
CREATE INDEX IF NOT EXISTS idx_query_log_response_status 
ON query_log(response_status);
CREATE INDEX IF NOT EXISTS idx_query_log_errors 
ON query_log(response_status) 
WHERE response_status != 'NOERROR';
