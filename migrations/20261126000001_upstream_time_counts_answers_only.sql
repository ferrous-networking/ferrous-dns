-- The upstream response time averaged every query that was not answered
-- locally, so a TIMEOUT or SERVFAIL added its whole wait, every pool and retry
-- included, and an outage held the average in seconds for the whole window.
-- It now averages the answers an upstream served, which the query log records
-- with the server that answered; the rest leave the minute rollups here.
WITH unanswered AS (
    SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60 AS bucket,
           query_source,
           COUNT(*) AS n,
           SUM(response_time_ms) AS us
    FROM query_log
    WHERE cache_hit = 0 AND blocked = 0 AND response_status IS NOT 'LOCAL_DNS'
      AND upstream_server IS NULL AND response_time_ms IS NOT NULL
      AND created_at IS NOT NULL
    GROUP BY 1, 2
)
UPDATE query_log_minute
SET upstream_timed = MAX(upstream_timed - unanswered.n, 0),
    upstream_response_us_sum = MAX(upstream_response_us_sum - unanswered.us, 0)
FROM unanswered
WHERE query_log_minute.bucket = unanswered.bucket
  AND query_log_minute.query_source = unanswered.query_source;
