-- Seeds the minute rollups from the rows already in query_log. This is also the
-- SQL reference for the writer's aggregation: the test suite replays it over the
-- raw rows and asserts it reproduces what the writer maintained incrementally.
INSERT INTO query_log_minute
SELECT
    (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60,
    query_source,
    COUNT(*),
    SUM(CASE WHEN blocked != 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN cache_hit != 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN cache_refresh != 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN cache_hit = 0 AND cache_refresh = 0 AND blocked = 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN response_status = 'LOCAL_DNS' THEN 1 ELSE 0 END),
    SUM(CASE WHEN response_status IN ('RATE_LIMITED', 'RATE_LIMITED_TC') THEN 1 ELSE 0 END),
    SUM(CASE WHEN blocked != 0
              AND block_source IN ('dns_rebinding', 'dns_tunneling', 'nxdomain_hijack',
                                   'response_ip_filter', 'dga_detection')
             THEN 1 ELSE 0 END),
    SUM(CASE WHEN dns64_synthesized != 0 THEN 1 ELSE 0 END),
    SUM(CASE WHEN dnssec_status IS NOT NULL THEN 1 ELSE 0 END),
    SUM(CASE WHEN dnssec_status = 'Secure' THEN 1 ELSE 0 END),
    SUM(CASE WHEN dnssec_status = 'Insecure' THEN 1 ELSE 0 END),
    SUM(CASE WHEN dnssec_status = 'Bogus' THEN 1 ELSE 0 END),
    SUM(CASE WHEN dnssec_status = 'Indeterminate' THEN 1 ELSE 0 END),
    SUM(CASE WHEN response_time_ms IS NOT NULL THEN 1 ELSE 0 END),
    COALESCE(SUM(response_time_ms), 0),
    SUM(CASE WHEN cache_hit != 0 AND response_time_ms IS NOT NULL THEN 1 ELSE 0 END),
    COALESCE(SUM(CASE WHEN cache_hit != 0 THEN response_time_ms END), 0),
    SUM(CASE WHEN cache_hit = 0 AND blocked = 0 AND response_status IS NOT 'LOCAL_DNS'
              AND response_time_ms IS NOT NULL
             THEN 1 ELSE 0 END),
    COALESCE(SUM(CASE WHEN cache_hit = 0 AND blocked = 0 AND response_status IS NOT 'LOCAL_DNS'
                      THEN response_time_ms END), 0)
FROM query_log
WHERE created_at IS NOT NULL
GROUP BY 1, 2;

INSERT INTO query_log_minute_record_type
SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60, record_type, COUNT(*)
FROM query_log
WHERE created_at IS NOT NULL AND query_source = 'client'
GROUP BY 1, 2;

INSERT INTO query_log_minute_block_source
SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60, block_source, COUNT(*)
FROM query_log
WHERE created_at IS NOT NULL AND query_source = 'client'
  AND blocked != 0 AND block_source IS NOT NULL
GROUP BY 1, 2;

INSERT INTO query_log_minute_upstream
SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60,
       COALESCE(upstream_pool, ''), COALESCE(upstream_server, ''), COUNT(*)
FROM query_log
WHERE created_at IS NOT NULL AND query_source = 'client'
  AND cache_hit = 0 AND blocked = 0 AND response_status IS NOT 'LOCAL_DNS'
GROUP BY 1, 2, 3;
