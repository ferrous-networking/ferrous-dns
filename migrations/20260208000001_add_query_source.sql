ALTER TABLE query_log ADD COLUMN query_source TEXT NOT NULL DEFAULT 'client';
CREATE INDEX IF NOT EXISTS idx_query_log_query_source ON query_log(query_source);
UPDATE query_log SET query_source = 'client' WHERE query_source IS NULL;
