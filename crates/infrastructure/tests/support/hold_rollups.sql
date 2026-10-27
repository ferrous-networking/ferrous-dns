-- Marks rollups rebuilt from every raw row as held the way the writer and the hourly
-- job leave them: every minute, and every hour before the current one, which stays
-- raw because the job only takes closed hours.
UPDATE query_log_rollup_state SET
    minute_since = 0,
    hour_since = 0,
    hour_until = CAST(strftime('%s', 'now') AS INTEGER) / 3600 * 3600,
    hour_floor = 0;
