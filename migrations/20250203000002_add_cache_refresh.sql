-- Add cache_refresh column to query_log
ALTER TABLE query_log ADD COLUMN cache_refresh INTEGER NOT NULL DEFAULT 0;

-- Create index for cache refresh queries
CREATE INDEX IF NOT EXISTS idx_query_log_cache_refresh ON query_log(cache_refresh) WHERE cache_refresh = 1;
