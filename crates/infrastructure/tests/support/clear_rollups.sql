-- Empties every query-log rollup, before a test rebuilds them from raw rows.
DELETE FROM query_log_minute;
DELETE FROM query_log_minute_record_type;
DELETE FROM query_log_minute_block_source;
DELETE FROM query_log_minute_upstream;
DELETE FROM query_log_hour_domain;
DELETE FROM query_log_hour_client;
