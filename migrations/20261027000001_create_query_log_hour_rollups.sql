-- Hourly aggregates of client queries for the top lists (top domains, distinct
-- domains, top clients). `bucket` is unix seconds (UTC) floored to the hour;
-- `blocked` is 0 or 1. The SQL reference for both tables is
-- crates/infrastructure/tests/support/hour_rollups.sql.
--
-- A background job fills them from the raw log, one closed hour at a time,
-- instead of the query-log writer: per-domain upserts on every flush halved the
-- writer's throughput. It also fills in the hours logged before this migration,
-- newest first, so a large log needs no backfill here to hold the first start.
CREATE TABLE query_log_hour_domain (
    bucket  INTEGER NOT NULL,
    domain  TEXT    NOT NULL,
    blocked INTEGER NOT NULL,
    count   INTEGER NOT NULL,
    PRIMARY KEY (bucket, domain, blocked)
) WITHOUT ROWID;

CREATE TABLE query_log_hour_client (
    bucket    INTEGER NOT NULL,
    client_ip TEXT    NOT NULL,
    blocked   INTEGER NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, client_ip, blocked)
) WITHOUT ROWID;

-- Which buckets the rollups hold completely, in one row; reads take every other
-- row from query_log, so results stay exact while the rollups fill in.
--   minute_since: minute buckets from here on (the writer keeps them).
--   hour_since, hour_until: hour buckets in [since, until) (the job keeps them).
--   hour_floor: retention's cutoff, rounded up; no hour before it is filled.
CREATE TABLE query_log_rollup_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    minute_since INTEGER NOT NULL,
    hour_since   INTEGER NOT NULL,
    hour_until   INTEGER NOT NULL,
    hour_floor   INTEGER NOT NULL
);

-- The minute rollups were backfilled, so only the oldest minute can be
-- incomplete: retention may have deleted part of it and kept the rest. No hour
-- is held yet; the job starts from the current one in both directions.
INSERT INTO query_log_rollup_state (id, minute_since, hour_since, hour_until, hour_floor)
SELECT 1,
       COALESCE((CAST(strftime('%s', MIN(created_at)) AS INTEGER) / 60 + 1) * 60, 0),
       CAST(strftime('%s', 'now') AS INTEGER) / 3600 * 3600,
       CAST(strftime('%s', 'now') AS INTEGER) / 3600 * 3600,
       0
FROM query_log
WHERE query_source = 'client';
