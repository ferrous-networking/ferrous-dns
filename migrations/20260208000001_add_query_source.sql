-- Phase 5: Add query_source to track internal vs client queries
-- This allows us to log internal DNS queries (DNSSEC validation, recursive resolution)
-- separately from client queries

-- Add query_source column (default 'client' for backward compatibility)
ALTER TABLE query_log ADD COLUMN query_source TEXT NOT NULL DEFAULT 'client';

-- Create index for efficient filtering by query source
CREATE INDEX IF NOT EXISTS idx_query_log_query_source ON query_log(query_source);

-- Update existing rows to explicitly set 'client' (optional, but good practice)
UPDATE query_log SET query_source = 'client' WHERE query_source IS NULL;
