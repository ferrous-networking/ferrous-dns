-- Per-minute aggregates of query_log, maintained by the query-log writer in the
-- same transaction as the raw rows. Dashboard stats and the timeline read these
-- instead of scanning query_log, so their windows are minute-aligned.
--
-- `bucket` is unix seconds (UTC) floored to the minute. Counters mirror the
-- predicates in the writer's `MinuteRollup::add`; the backfill migration that
-- follows is the SQL reference for the same definitions.
CREATE TABLE query_log_minute (
    bucket                   INTEGER NOT NULL,
    query_source             TEXT    NOT NULL,
    total                    INTEGER NOT NULL,
    blocked                  INTEGER NOT NULL,
    cache_hits               INTEGER NOT NULL,
    cache_refreshes          INTEGER NOT NULL,
    cache_misses             INTEGER NOT NULL,
    local_dns                INTEGER NOT NULL,
    rate_limited             INTEGER NOT NULL,
    malware                  INTEGER NOT NULL,
    dns64_synthesized        INTEGER NOT NULL,
    dnssec_validated         INTEGER NOT NULL,
    dnssec_secure            INTEGER NOT NULL,
    dnssec_insecure          INTEGER NOT NULL,
    dnssec_bogus             INTEGER NOT NULL,
    dnssec_indeterminate     INTEGER NOT NULL,
    timed                    INTEGER NOT NULL,
    response_us_sum          INTEGER NOT NULL,
    cache_timed              INTEGER NOT NULL,
    cache_response_us_sum    INTEGER NOT NULL,
    upstream_timed           INTEGER NOT NULL,
    upstream_response_us_sum INTEGER NOT NULL,
    PRIMARY KEY (bucket, query_source)
) WITHOUT ROWID;

-- Breakdowns cover client queries only: every reader of them filters on it.
CREATE TABLE query_log_minute_record_type (
    bucket      INTEGER NOT NULL,
    record_type TEXT    NOT NULL,
    count       INTEGER NOT NULL,
    PRIMARY KEY (bucket, record_type)
) WITHOUT ROWID;

CREATE TABLE query_log_minute_block_source (
    bucket       INTEGER NOT NULL,
    block_source TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    PRIMARY KEY (bucket, block_source)
) WITHOUT ROWID;

-- '' stands for an unrecorded pool/server: primary-key columns cannot be NULL.
CREATE TABLE query_log_minute_upstream (
    bucket          INTEGER NOT NULL,
    upstream_pool   TEXT    NOT NULL,
    upstream_server TEXT    NOT NULL,
    count           INTEGER NOT NULL,
    PRIMARY KEY (bucket, upstream_pool, upstream_server)
) WITHOUT ROWID;

-- With aggregates off query_log, the raw table only serves windowed scans
-- (log view, top-N, rate, retention). One narrow index replaces five, most of
-- them wide covering indexes on the insert path. Source-first gives every
-- windowed read an equality-then-range seek; retention, which has no source
-- predicate, skip-scans the three source values once stats exist.
DROP INDEX IF EXISTS idx_query_log_query_source;
DROP INDEX IF EXISTS idx_query_log_stats_coverage;
DROP INDEX IF EXISTS idx_query_log_cache_stats;
DROP INDEX IF EXISTS idx_query_log_source_created;
DROP INDEX IF EXISTS idx_query_log_retention;

CREATE INDEX idx_query_log_window ON query_log(query_source, created_at, blocked);
