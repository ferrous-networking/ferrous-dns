-- Declarative definition of the hourly rollups the hourly job fills
-- (migrations/20261027000001_create_query_log_hour_rollups.sql). There is no
-- backfill migration, so this file is the reference: test helpers rebuild the
-- rollups with it after seeding raw rows, and query_log_rollup_reads_test checks
-- the job against the raw log.
INSERT INTO query_log_hour_domain
SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 3600) * 3600, domain, blocked != 0, COUNT(*)
FROM query_log
WHERE created_at IS NOT NULL AND query_source = 'client'
GROUP BY 1, 2, 3;

INSERT INTO query_log_hour_client
SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 3600) * 3600, client_ip, blocked != 0, COUNT(*)
FROM query_log
WHERE created_at IS NOT NULL AND query_source = 'client'
GROUP BY 1, 2, 3;
