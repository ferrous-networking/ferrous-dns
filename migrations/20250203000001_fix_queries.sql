-- Fix existing query_log entries that have NULL response_time_ms
-- This happens because old queries were logged before the fix

-- Option 1: Delete old queries without response_time (clean start)
DELETE FROM query_log WHERE response_time_ms IS NULL;

-- Option 2: Or set a default value for old queries (if you want to keep them)
-- UPDATE query_log SET response_time_ms = 0 WHERE response_time_ms IS NULL;
