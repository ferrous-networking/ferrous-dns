-- Change response_time from milliseconds to microseconds for better precision
-- This is a comment for migration history, no actual change needed to column type (still INTEGER)
-- We'll just change how we store the value in the application code

-- Note: SQLite doesn't support ALTER COLUMN, so we just document the unit change
-- Old: response_time_ms in milliseconds
-- New: response_time_us in microseconds (stored in same column, renamed logically)
