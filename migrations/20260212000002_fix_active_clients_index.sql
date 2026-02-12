-- ============================================================================
-- Fix: Remove non-deterministic datetime() from partial index
-- ============================================================================
-- Problem: The idx_clients_active index uses datetime('now', '-1 day')
-- which SQLite considers non-deterministic for INSERT/UPDATE operations
--
-- Solution: Drop the problematic index
-- We can filter on last_seen in queries without the partial index

DROP INDEX IF EXISTS idx_clients_active;

-- The regular idx_clients_last_seen is sufficient for most queries
-- If needed, we can add filtering in application layer:
-- SELECT * FROM clients WHERE last_seen > datetime('now', '-1 day')
