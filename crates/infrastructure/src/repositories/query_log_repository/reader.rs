use super::helpers::{row_to_query_log, window_start_bucket};
use super::hour_rollup;
use super::rollup;
use crate::repositories::{
    db_err, hours_ago, hours_ago_cutoff, seconds_ago_cutoff, sql_ts, unix_cutoff,
};
use chrono::{DateTime, TimeDelta, Utc};
use ferrous_dns_application::ports::{ClientActivity, PageAt, PagedQueryResult, QueryLogStorage};
use ferrous_dns_domain::entities::query_log::{
    ClientProtocol, DnssecStats, DnssecStatusFilter, QueryCategory, QueryLogFilter,
};
use ferrous_dns_domain::{BlockResponseMode, DomainError, QueryLog, QueryStats};
use sqlx::{Row, SqlitePool};
use std::time::{Duration, Instant};
use tracing::{debug, info, instrument};

/// SQL mirror of `BlockSource::is_malware`; the rollup backfill carries the same list.
const MALWARE_FILTER: &str = " AND q.block_source IN ('dns_tunneling', 'dns_rebinding', 'nxdomain_hijack', 'response_ip_filter', 'dga_detection')";

/// SQL mirror of `QueryLog::reply_kind`, yielding `ReplyKind::as_str`; change
/// both together. `block_mode` picks the branch for an ordinary block.
fn reply_kind_sql(block_mode: BlockResponseMode) -> String {
    let blocked = match block_mode {
        BlockResponseMode::NullIp => {
            "CASE WHEN q.record_type IN ('A', 'AAAA') THEN 'IP' ELSE 'NODATA' END"
        }
        BlockResponseMode::NoData => "'NODATA'",
        BlockResponseMode::NxDomain => "'NXDOMAIN'",
        BlockResponseMode::Refused => "'REFUSED'",
    };
    format!(
        "CASE
            WHEN q.blocked = 1 THEN CASE
                WHEN q.block_source = 'nxdomain_hijack' THEN 'NXDOMAIN'
                WHEN q.response_status = 'RATE_LIMITED' THEN 'REFUSED'
                WHEN q.response_status = 'RATE_LIMITED_TC' THEN 'OTHER'
                ELSE {blocked} END
            WHEN q.response_status IN ('NOERROR', 'LOCAL_DNS')
                 AND q.answers IS NOT NULL AND q.answers <> '' THEN 'IP'
            WHEN q.response_status = 'NOERROR' AND q.record_type IN ('A', 'AAAA') THEN 'NODATA'
            WHEN q.response_status = 'NOERROR' THEN 'OTHER'
            WHEN q.response_status = 'SAFE_SEARCH' THEN 'CNAME'
            WHEN q.response_status IN ('NXDOMAIN', 'SERVFAIL', 'REFUSED') THEN q.response_status
            WHEN q.response_status = 'TIMEOUT' THEN 'NONE'
            ELSE 'UNKNOWN' END"
    )
}

/// Every column `row_to_query_log` reads, joined to the client hostname, followed by `$tail`.
macro_rules! select_query_log {
    ($tail:literal) => {
        concat!(
            "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                    q.cache_hit, q.cache_refresh, q.dnssec_status, q.dns64_synthesized, q.answers, q.upstream_server,
                    q.upstream_pool, q.response_status, q.query_source, q.protocol, q.group_id, q.block_source, q.coalesced,
                    datetime(q.created_at) AS created_at, c.hostname
             FROM query_log q
             LEFT JOIN clients c ON q.client_ip = c.ip_address",
            $tail
        )
    };
}

/// `%needle%` for `LIKE ? ESCAPE '\'`, so `%`, `_` and `\` in user input match literally.
fn contains_pattern(needle: &str) -> String {
    let mut pattern = String::with_capacity(needle.len() + 2);
    pattern.push('%');
    for ch in needle.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

/// Client rows logged since `start`: raw rows up to the first complete minute,
/// then the minute rollups.
async fn count_client_rows_since(
    pool: &SqlitePool,
    start: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    let cutoff = sql_ts(start);
    let switch_bucket = rollup::first_complete_minute(pool, start.timestamp()).await?;
    // The bucket lies between `start` and a stored minute, inside chrono's range.
    let switch_at = unix_cutoff(switch_bucket).unwrap_or_else(|| cutoff.clone());
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM query_log
                 WHERE query_source = 'client' AND created_at >= ? AND created_at < ?)
              + (SELECT COALESCE(SUM(total), 0) FROM query_log_minute
                 WHERE query_source = 'client' AND bucket >= ?)",
    )
    .bind(&cutoff)
    .bind(&switch_at)
    .bind(switch_bucket)
    .fetch_one(pool)
    .await
}

/// Binds a window's three parts in the order of the hour-rollup reads: the raw lead,
/// the buckets, then the raw tail.
macro_rules! bind_hour_split {
    ($query:expr, $split:expr) => {
        $query
            .bind(&$split.cutoff)
            .bind(&$split.lead_end)
            .bind($split.from)
            .bind($split.until)
            .bind(&$split.tail_start)
    };
}

#[instrument(skip(pool))]
pub(super) async fn get_recent(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<QueryLog>, DomainError> {
    debug!(
        limit,
        period_hours, "Fetching recent queries with time filter"
    );

    let rows = sqlx::query(select_query_log!(
        " WHERE q.created_at >= ?
            AND q.query_source = 'client'
          ORDER BY q.created_at DESC, q.id DESC
          LIMIT ?"
    ))
    .bind(hours_ago_cutoff(period_hours))
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(db_err("Failed to fetch recent queries"))?;

    let entries: Vec<QueryLog> = rows.into_iter().filter_map(row_to_query_log).collect();
    debug!(count = entries.len(), "Recent queries fetched successfully");
    Ok(entries)
}

#[instrument(skip(pool))]
pub(super) async fn get_recent_paged(
    pool: &SqlitePool,
    limit: u32,
    page: PageAt,
    period_hours: f32,
    filter: &QueryLogFilter,
) -> Result<PagedQueryResult, DomainError> {
    debug!(
        limit,
        ?page,
        period_hours,
        ?filter,
        "Fetching paginated queries"
    );

    let fetch_limit = limit as i64 + 1;
    let window_start = hours_ago(period_hours);
    let cutoff = sql_ts(window_start);
    let domain_pattern = filter
        .domain
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(contains_pattern);
    let client_pattern = filter
        .client
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(contains_pattern);

    // Every fragment is static SQL; user input only ever reaches the query as a bind.
    let category_clause = match filter.category {
        Some(QueryCategory::Allowed) => " AND q.blocked = 0",
        Some(QueryCategory::Blocked) => " AND q.blocked = 1",
        Some(QueryCategory::Cache) => " AND q.cache_hit = 1",
        Some(QueryCategory::Upstream) => " AND q.cache_hit = 0 AND q.blocked = 0 AND (q.response_status IS NULL OR q.response_status NOT IN ('LOCAL_DNS', 'RATE_LIMITED', 'RATE_LIMITED_TC'))",
        Some(QueryCategory::RateLimited) => " AND q.response_status IN ('RATE_LIMITED', 'RATE_LIMITED_TC')",
        Some(QueryCategory::Malware) => MALWARE_FILTER,
        None => "",
    };
    let domain_clause = if domain_pattern.is_some() {
        " AND q.domain LIKE ? ESCAPE '\\'"
    } else {
        ""
    };
    let client_clause = if client_pattern.is_some() {
        " AND (q.client_ip LIKE ? ESCAPE '\\' OR c.hostname LIKE ? ESCAPE '\\')"
    } else {
        ""
    };
    let type_clause = if filter.record_type.is_some() {
        " AND q.record_type = ?"
    } else {
        ""
    };
    let upstream_clause = if filter.upstream.is_some() {
        " AND q.upstream_server = ?"
    } else {
        ""
    };
    let dnssec_clause = match filter.dnssec_status {
        Some(DnssecStatusFilter::Any) => " AND q.dnssec_status IS NOT NULL",
        Some(DnssecStatusFilter::Is(_)) => " AND q.dnssec_status = ?",
        Some(DnssecStatusFilter::NotValidated) => " AND q.dnssec_status IS NULL",
        None => "",
    };
    let dns64_clause = match filter.dns64_synthesized {
        Some(true) => " AND q.dns64_synthesized = 1",
        Some(false) => " AND q.dns64_synthesized = 0",
        None => "",
    };
    let protocol_clause = match filter.protocol {
        Some(ClientProtocol::Udp) => " AND q.protocol = 'udp'",
        Some(ClientProtocol::Tcp) => " AND q.protocol = 'tcp'",
        Some(ClientProtocol::Dot) => " AND q.protocol = 'dot'",
        Some(ClientProtocol::Doh) => " AND q.protocol = 'doh'",
        Some(ClientProtocol::Doq) => " AND q.protocol = 'doq'",
        None => "",
    };
    let until = filter.until.and_then(unix_cutoff);
    let until_clause = if until.is_some() {
        " AND q.created_at < ?"
    } else {
        ""
    };
    let excluded_types_clause = if filter.excluded_record_types.is_empty() {
        String::new()
    } else {
        let placeholders = vec!["?"; filter.excluded_record_types.len()].join(", ");
        format!(" AND q.record_type NOT IN ({placeholders})")
    };
    let reply_clause = filter.reply.map_or_else(String::new, |reply| {
        format!(" AND ({}) = ?", reply_kind_sql(reply.block_mode))
    });
    let filters = [
        domain_clause,
        category_clause,
        client_clause,
        type_clause,
        upstream_clause,
        dnssec_clause,
        dns64_clause,
        protocol_clause,
        until_clause,
        &excluded_types_clause,
        &reply_clause,
    ]
    .concat();
    // A snapshot page counts its matches within the snapshot too.
    let newest_id = match page {
        PageAt::Snapshot { newest_id, .. } => Some(newest_id),
        PageAt::Offset(_) | PageAt::Cursor(_) => None,
    };
    let snapshot_clause = if newest_id.is_some() {
        " AND q.id <= ?"
    } else {
        ""
    };
    // With nothing to filter on, the filtered count is the total.
    let is_unfiltered = filters.is_empty() && newest_id.is_none();

    // Binds the `?` of `filters`, in the order its fragments are concatenated.
    macro_rules! bind_filters {
        ($query:expr) => {{
            let mut q = $query;
            if let Some(ref pat) = domain_pattern {
                q = q.bind(pat);
            }
            if let Some(ref pat) = client_pattern {
                q = q.bind(pat).bind(pat);
            }
            if let Some(ref rt) = filter.record_type {
                q = q.bind(rt.as_str());
            }
            if let Some(ref up) = filter.upstream {
                q = q.bind(up);
            }
            if let Some(DnssecStatusFilter::Is(status)) = filter.dnssec_status {
                q = q.bind(status.as_str());
            }
            if let Some(ref until) = until {
                q = q.bind(until);
            }
            for record_type in &filter.excluded_record_types {
                q = q.bind(record_type.as_str());
            }
            if let Some(reply) = filter.reply {
                q = q.bind(reply.kind.as_str());
            }
            q
        }};
    }

    let (rows_result, filtered_count_result, total_count_result) = tokio::join!(
        async {
            // Every page orders by `(created_at, id)`: `id` breaks the ties of a
            // flush, which stamps its whole batch alike. A cursor page continues
            // after the cursor row's key, not its id alone, since a backwards
            // clock step gives newer rows (higher ids) older timestamps. A cursor
            // row deleted by retention has no key left, so the page continues
            // below its id, which is monotonic.
            match page {
                PageAt::Cursor(cursor_id) => {
                    let sql = format!(
                        select_query_log!(
                            " WHERE CASE WHEN EXISTS (SELECT 1 FROM query_log c WHERE c.id = ?)
                                    THEN (q.created_at, q.id) <
                                         (SELECT c.created_at, c.id FROM query_log c WHERE c.id = ?)
                                    ELSE q.id < ? END
                                AND q.query_source = 'client'
                                AND q.created_at >= ?{filters}
                              ORDER BY q.created_at DESC, q.id DESC
                              LIMIT ?"
                        ),
                        filters = filters
                    );
                    let q = sqlx::query(&sql)
                        .bind(cursor_id)
                        .bind(cursor_id)
                        .bind(cursor_id)
                        .bind(&cutoff);
                    bind_filters!(q).bind(fetch_limit).fetch_all(pool).await
                }
                PageAt::Offset(offset) => {
                    let sql = format!(
                        select_query_log!(
                            " WHERE q.created_at >= ?
                                AND q.query_source = 'client'{filters}
                              ORDER BY q.created_at DESC, q.id DESC
                              LIMIT ? OFFSET ?"
                        ),
                        filters = filters
                    );
                    let q = sqlx::query(&sql).bind(&cutoff);
                    bind_filters!(q)
                        .bind(fetch_limit)
                        .bind(i64::from(offset))
                        .fetch_all(pool)
                        .await
                }
                PageAt::Snapshot { newest_id, offset } => {
                    let sql = format!(
                        select_query_log!(
                            " WHERE q.created_at >= ?
                                AND q.query_source = 'client'
                                AND q.id <= ?{filters}
                              ORDER BY q.created_at DESC, q.id DESC
                              LIMIT ? OFFSET ?"
                        ),
                        filters = filters
                    );
                    let q = sqlx::query(&sql).bind(&cutoff).bind(newest_id);
                    bind_filters!(q)
                        .bind(fetch_limit)
                        .bind(i64::from(offset))
                        .fetch_all(pool)
                        .await
                }
            }
        },
        async {
            if is_unfiltered {
                return Ok(None);
            }
            let count_sql = format!(
                "SELECT COUNT(*) as cnt FROM query_log q
                 LEFT JOIN clients c ON q.client_ip = c.ip_address
                 WHERE q.query_source = 'client' AND q.created_at >= ?{snapshot_clause}{filters}"
            );
            let mut q = sqlx::query(&count_sql).bind(&cutoff);
            if let Some(newest_id) = newest_id {
                q = q.bind(newest_id);
            }
            bind_filters!(q)
                .fetch_one(pool)
                .await
                .map(|row| Some(row.get::<i64, _>("cnt")))
        },
        count_client_rows_since(pool, window_start)
    );

    let mut rows = rows_result.map_err(db_err("Failed to fetch paginated queries"))?;
    let records_total = total_count_result.map_err(db_err("Failed to count total queries"))? as u64;
    let records_filtered = filtered_count_result
        .map_err(db_err("Failed to count filtered queries"))?
        .map_or(records_total, |n| n as u64);

    let has_more = rows.len() as u32 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        rows.last().map(|r| r.get::<i64, _>("id"))
    } else {
        None
    };

    let entries: Vec<QueryLog> = rows.into_iter().filter_map(row_to_query_log).collect();

    debug!(
        count = entries.len(),
        records_total, records_filtered, next_cursor, "Paginated queries fetched"
    );
    Ok(PagedQueryResult {
        queries: entries,
        records_total,
        records_filtered,
        next_cursor,
    })
}

/// Mean of a microsecond sum over `n` samples, in milliseconds.
fn mean_ms(sum_us: i64, n: i64) -> f64 {
    if n > 0 {
        sum_us as f64 / n as f64 / 1000.0
    } else {
        0.0
    }
}

#[instrument(skip(pool))]
pub(super) async fn get_stats(
    pool: &SqlitePool,
    period_hours: f32,
    started_at: Instant,
) -> Result<QueryStats, DomainError> {
    let since = window_start_bucket(period_hours);

    let (totals, type_rows, block_source_rows, upstream_rows) = tokio::join!(
        sqlx::query(
            "SELECT COALESCE(SUM(total), 0) AS total,
                    COALESCE(SUM(blocked), 0) AS blocked,
                    COALESCE(SUM(rate_limited), 0) AS rate_limited,
                    COALESCE(SUM(malware), 0) AS malware,
                    COALESCE(SUM(dnssec_bogus), 0) AS dnssec_bogus,
                    COALESCE(SUM(dns64_synthesized), 0) AS dns64_synthesized,
                    COALESCE(SUM(cache_hits), 0) AS cache_hits,
                    COALESCE(SUM(local_dns), 0) AS local_dns,
                    COALESCE(SUM(timed), 0) AS timed,
                    COALESCE(SUM(response_us_sum), 0) AS response_us_sum,
                    COALESCE(SUM(cache_timed), 0) AS cache_timed,
                    COALESCE(SUM(cache_response_us_sum), 0) AS cache_response_us_sum,
                    COALESCE(SUM(upstream_timed), 0) AS upstream_timed,
                    COALESCE(SUM(upstream_response_us_sum), 0) AS upstream_response_us_sum
             FROM query_log_minute
             WHERE bucket >= ? AND query_source = 'client'",
        )
        .bind(since)
        .fetch_one(pool),
        sqlx::query(
            "SELECT record_type, SUM(count) AS count
             FROM query_log_minute_record_type
             WHERE bucket >= ?
             GROUP BY record_type",
        )
        .bind(since)
        .fetch_all(pool),
        sqlx::query(
            "SELECT block_source, SUM(count) AS count
             FROM query_log_minute_block_source
             WHERE bucket >= ?
             GROUP BY block_source",
        )
        .bind(since)
        .fetch_all(pool),
        sqlx::query(
            "SELECT upstream_pool, upstream_server, SUM(count) AS count
             FROM query_log_minute_upstream
             WHERE bucket >= ?
             GROUP BY upstream_pool, upstream_server",
        )
        .bind(since)
        .fetch_all(pool),
    );

    let row = totals.map_err(db_err("Failed to fetch statistics"))?;
    let type_rows = type_rows.map_err(db_err("Failed to fetch type distribution"))?;
    let block_source_rows =
        block_source_rows.map_err(db_err("Failed to fetch block source statistics"))?;
    let upstream_rows = upstream_rows.map_err(db_err("Failed to fetch upstream statistics"))?;

    let col = |name: &str| row.get::<i64, _>(name);
    let total = col("total") as u64;
    let cache_hits = col("cache_hits") as u64;
    let cache_hit_rate = if total > 0 {
        (cache_hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let mut queries_by_type = std::collections::HashMap::new();
    for type_row in type_rows {
        let type_str: String = type_row.get("record_type");
        if let Ok(record_type) = type_str.parse::<ferrous_dns_domain::RecordType>() {
            queries_by_type.insert(record_type, type_row.get::<i64, _>("count") as u64);
        }
    }

    let mut source_stats = std::collections::HashMap::new();
    source_stats.insert("cache".to_string(), cache_hits);
    source_stats.insert("local_dns".to_string(), col("local_dns") as u64);
    for upstream_row in upstream_rows {
        let count = upstream_row.get::<i64, _>("count") as u64;
        if count == 0 {
            continue;
        }
        // '' is the rollup's encoding of an unrecorded pool/server.
        let name = |column: &str| {
            let value: String = upstream_row.get(column);
            if value.is_empty() {
                "unknown".to_string()
            } else {
                value
            }
        };
        source_stats.insert(
            format!("{}:{}", name("upstream_pool"), name("upstream_server")),
            count,
        );
    }
    for block_row in block_source_rows {
        let count = block_row.get::<i64, _>("count") as u64;
        if count > 0 {
            source_stats.insert(block_row.get("block_source"), count);
        }
    }

    let stats = QueryStats {
        queries_total: total,
        queries_blocked: col("blocked") as u64,
        queries_rate_limited: col("rate_limited") as u64,
        queries_malware_detected: col("malware") as u64,
        queries_dnssec_bogus: col("dnssec_bogus") as u64,
        queries_dns64_synthesized: col("dns64_synthesized") as u64,
        unique_clients: 0,
        uptime_seconds: started_at.elapsed().as_secs(),
        cache_hit_rate,
        avg_query_time_ms: mean_ms(col("response_us_sum"), col("timed")),
        avg_cache_time_ms: mean_ms(col("cache_response_us_sum"), col("cache_timed")),
        avg_upstream_time_ms: mean_ms(col("upstream_response_us_sum"), col("upstream_timed")),
        source_stats,
        queries_by_type: std::collections::HashMap::new(),
        most_queried_type: None,
        record_type_distribution: Vec::new(),
    }
    .with_analytics(queries_by_type);

    debug!(
        queries_total = stats.queries_total,
        queries_blocked = stats.queries_blocked,
        cache_hit_rate = stats.cache_hit_rate,
        "Statistics fetched successfully"
    );
    Ok(stats)
}

#[instrument(skip(pool))]
pub(super) async fn get_dnssec_stats(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<DnssecStats, DomainError> {
    let row = sqlx::query(
        "SELECT COALESCE(SUM(total), 0) AS total,
                COALESCE(SUM(dnssec_validated), 0) AS validated,
                COALESCE(SUM(dnssec_secure), 0) AS secure,
                COALESCE(SUM(dnssec_insecure), 0) AS insecure,
                COALESCE(SUM(dnssec_bogus), 0) AS bogus,
                COALESCE(SUM(dnssec_indeterminate), 0) AS indeterminate
         FROM query_log_minute
         WHERE bucket >= ? AND query_source = 'client'",
    )
    .bind(window_start_bucket(period_hours))
    .fetch_one(pool)
    .await
    .map_err(db_err("Failed to fetch DNSSEC statistics"))?;

    let count = |col: &str| row.get::<i64, _>(col) as u64;
    Ok(DnssecStats {
        total: count("total"),
        validated: count("validated"),
        secure: count("secure"),
        insecure: count("insecure"),
        bogus: count("bogus"),
        indeterminate: count("indeterminate"),
    })
}

/// Exact-to-the-second, so it reads the raw rows; the window index makes it an
/// index-only range count.
#[instrument(skip(pool))]
pub(super) async fn count_queries_since(
    pool: &SqlitePool,
    seconds_ago: i64,
) -> Result<u64, DomainError> {
    let cutoff = seconds_ago_cutoff(seconds_ago);
    let row = sqlx::query(
        "SELECT COUNT(*) as count FROM query_log WHERE created_at >= ? AND query_source = 'client'",
    )
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .map_err(db_err("Failed to count queries"))?;

    Ok(row.get::<i64, _>("count") as u64)
}

#[instrument(skip(pool))]
pub(super) async fn get_cache_stats(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<ferrous_dns_application::ports::CacheStats, DomainError> {
    // Refreshes are internal lookups, so only they are counted across sources.
    let row = sqlx::query(
        "SELECT COALESCE(SUM(CASE WHEN query_source = 'client' THEN total END), 0) AS total_queries,
                COALESCE(SUM(CASE WHEN query_source = 'client' THEN cache_hits END), 0) AS hits,
                COALESCE(SUM(cache_refreshes), 0) AS refreshes,
                COALESCE(SUM(CASE WHEN query_source = 'client' THEN cache_misses END), 0) AS misses
         FROM query_log_minute
         WHERE bucket >= ?",
    )
    .bind(window_start_bucket(period_hours))
    .fetch_one(pool)
    .await
    .map_err(db_err("Failed to fetch cache statistics"))?;

    let total_hits = row.get::<i64, _>("hits") as u64;
    let total_misses = row.get::<i64, _>("misses") as u64;
    let total_refreshes = row.get::<i64, _>("refreshes") as u64;
    let total_queries = row.get::<i64, _>("total_queries") as u64;

    let hit_rate = if total_queries > 0 {
        (total_hits as f64 / total_queries as f64) * 100.0
    } else {
        0.0
    };

    let refresh_rate = if total_hits > 0 {
        (total_refreshes as f64 / total_hits as f64) * 100.0
    } else {
        0.0
    };

    Ok(ferrous_dns_application::ports::CacheStats {
        total_hits,
        total_misses,
        total_refreshes,
        hit_rate,
        refresh_rate,
    })
}

/// Which rows a top-domains ranking counts.
#[derive(Debug, Clone, Copy)]
pub(super) enum DomainVerdict {
    Blocked,
    Allowed,
    Any,
}

/// Counts per `$key` over a window split by `split_hours`: the raw lead, the hourly
/// rollup `$table`, and the raw tail, each narrowed by `$verdict`.
macro_rules! hour_split_counts_sql {
    ($key:literal, $table:literal, $verdict:literal) => {
        concat!(
            "SELECT ",
            $key,
            ", SUM(n) AS count FROM (
                 SELECT ",
            $key,
            ", COUNT(*) AS n FROM query_log
                 WHERE query_source = 'client' AND created_at >= ? AND created_at < ?",
            $verdict,
            "
                 GROUP BY ",
            $key,
            "
                 UNION ALL
                 SELECT ",
            $key,
            ", SUM(count) AS n FROM ",
            $table,
            "
                 WHERE bucket >= ? AND bucket < ?",
            $verdict,
            "
                 GROUP BY ",
            $key,
            "
                 UNION ALL
                 SELECT ",
            $key,
            ", COUNT(*) AS n FROM query_log
                 WHERE query_source = 'client' AND created_at >= ?",
            $verdict,
            "
                 GROUP BY ",
            $key,
            "
             )
             GROUP BY ",
            $key,
            "
             ORDER BY count DESC
             LIMIT ?"
        )
    };
}

macro_rules! top_domains_sql {
    ($verdict:literal) => {
        hour_split_counts_sql!("domain", "query_log_hour_domain", $verdict)
    };
}

/// Hourly rollups where they hold the window, raw rows around them.
#[instrument(skip(pool))]
pub(super) async fn get_top_domains(
    pool: &SqlitePool,
    verdict: DomainVerdict,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<(String, u64)>, DomainError> {
    let (sql, context) = match verdict {
        DomainVerdict::Blocked => (
            top_domains_sql!(" AND blocked = 1"),
            "Failed to fetch top blocked domains",
        ),
        DomainVerdict::Allowed => (
            top_domains_sql!(" AND blocked = 0"),
            "Failed to fetch top allowed domains",
        ),
        DomainVerdict::Any => (
            top_domains_sql!(""),
            "Failed to fetch distinct recent domains",
        ),
    };
    let split = hour_rollup::split_hours(pool, hours_ago(period_hours))
        .await
        .map_err(db_err(context))?;
    let rows = bind_hour_split!(sqlx::query(sql), split)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .map_err(db_err(context))?;

    Ok(rows
        .into_iter()
        .map(|r| (r.get("domain"), r.get::<i64, _>("count") as u64))
        .collect())
}

#[instrument(skip(pool))]
pub(super) async fn count_distinct_domains(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<u64, DomainError> {
    let split = hour_rollup::split_hours(pool, hours_ago(period_hours))
        .await
        .map_err(db_err("Failed to count distinct domains"))?;
    let row = bind_hour_split!(
        sqlx::query(
            "SELECT COUNT(*) AS count FROM (
             SELECT domain FROM query_log
             WHERE query_source = 'client' AND created_at >= ? AND created_at < ?
             UNION
             SELECT domain FROM query_log_hour_domain WHERE bucket >= ? AND bucket < ?
             UNION
             SELECT domain FROM query_log WHERE query_source = 'client' AND created_at >= ?
         )",
        ),
        split
    )
    .fetch_one(pool)
    .await
    .map_err(db_err("Failed to count distinct domains"))?;

    Ok(row.get::<i64, _>("count") as u64)
}

/// The top clients by count, with the hostname looked up once per listed client.
macro_rules! top_clients_sql {
    ($verdict:literal) => {
        concat!(
            "SELECT t.client_ip, c.hostname, t.count FROM (",
            hour_split_counts_sql!("client_ip", "query_log_hour_client", $verdict),
            ") t
             LEFT JOIN clients c ON t.client_ip = c.ip_address
             ORDER BY t.count DESC"
        )
    };
}

#[instrument(skip(pool))]
pub(super) async fn get_top_clients(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
    blocked_only: bool,
) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
    let split = hour_rollup::split_hours(pool, hours_ago(period_hours))
        .await
        .map_err(db_err("Failed to fetch top clients"))?;
    let sql = if blocked_only {
        top_clients_sql!(" AND blocked = 1")
    } else {
        top_clients_sql!("")
    };
    let rows = bind_hour_split!(sqlx::query(sql), split)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .map_err(db_err("Failed to fetch top clients"))?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let ip: String = r.get("client_ip");
            let hostname: Option<String> = r.get("hostname");
            let count = r.get::<i64, _>("count") as u64;
            (ip, hostname, count)
        })
        .collect())
}

/// Per-bucket counts from the raw log: the rollups do not keep the client.
/// Clients outside `clients` come back with a NULL ip, one row per bucket.
#[instrument(skip(pool, clients))]
pub(super) async fn get_client_activity(
    pool: &SqlitePool,
    clients: &[String],
    bucket_secs: u32,
    period_hours: f32,
) -> Result<Vec<ClientActivity>, DomainError> {
    let cutoff = hours_ago_cutoff(period_hours);
    let clients_json = serde_json::to_string(clients)
        .map_err(|e| DomainError::InvalidInput(format!("invalid client list: {e}")))?;
    let rows = sqlx::query(
        "SELECT (CAST(strftime('%s', created_at) AS INTEGER) / ?) * ? AS bucket,
                CASE WHEN client_ip IN (SELECT value FROM json_each(?))
                     THEN client_ip END AS client,
                COUNT(*) AS count
         FROM query_log
         WHERE created_at >= ?
           AND query_source = 'client'
         GROUP BY bucket, client
         ORDER BY bucket ASC",
    )
    .bind(i64::from(bucket_secs))
    .bind(i64::from(bucket_secs))
    .bind(clients_json)
    .bind(cutoff)
    .fetch_all(pool)
    .await
    .map_err(db_err("Failed to fetch client activity"))?;

    Ok(rows
        .into_iter()
        .map(|r| ClientActivity {
            bucket: r.get("bucket"),
            client_ip: r.get("client"),
            count: r.get::<i64, _>("count") as u64,
        })
        .collect())
}

/// The whole client log and the period's share of it, counted from the minute
/// rollups; the oldest timestamp of each and the newest id are index seeks.
#[instrument(skip(pool))]
pub(super) async fn get_storage(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<QueryLogStorage, DomainError> {
    const CONTEXT: &str = "Failed to read query log storage";
    let window_start = hours_ago(period_hours);
    let (stored, recent) = tokio::try_join!(
        count_client_rows_since(pool, DateTime::<Utc>::MIN_UTC),
        count_client_rows_since(pool, window_start),
    )
    .map_err(db_err(CONTEXT))?;
    // `+query_source` keeps the window index out of the newest-id lookup: walking ids
    // down from the top finds a client row at once, the index would sort them all.
    let row = sqlx::query(
        "SELECT COALESCE((SELECT CAST(strftime('%s', MIN(created_at)) AS REAL)
                          FROM query_log WHERE query_source = 'client'), 0.0) AS stored_earliest,
                COALESCE((SELECT CAST(strftime('%s', MIN(created_at)) AS REAL)
                          FROM query_log
                          WHERE query_source = 'client' AND created_at >= ?), 0.0) AS recent_earliest,
                COALESCE((SELECT id FROM query_log WHERE +query_source = 'client'
                          ORDER BY id DESC LIMIT 1), 0) AS newest_id,
                sqlite_version() AS sqlite_version",
    )
    .bind(sql_ts(window_start))
    .fetch_one(pool)
    .await
    .map_err(db_err(CONTEXT))?;

    Ok(QueryLogStorage {
        recent_queries: recent as u64,
        recent_earliest: row.get("recent_earliest"),
        stored_queries: stored as u64,
        stored_earliest: row.get("stored_earliest"),
        newest_id: row.get("newest_id"),
        sqlite_version: row.get("sqlite_version"),
    })
}

pub(super) async fn delete_older_than(pool: &SqlitePool, days: u32) -> Result<u64, DomainError> {
    // A retention reaching past the calendar's start means no row is old enough.
    let Some(cutoff_at) = Utc::now().checked_sub_signed(TimeDelta::days(i64::from(days))) else {
        return Ok(0);
    };
    let cutoff = sql_ts(cutoff_at);
    let mut total_deleted: u64 = 0;

    // Rollups first: from here on, reads take everything before the cutoff from the
    // raw rows, so they stay exact while the batches below delete them. A bucket
    // straddling the cutoff goes whole, so `days = 0` clears everything.
    rollup::prune_before(pool, cutoff_at.timestamp())
        .await
        .map_err(db_err("Failed to prune query log rollups"))?;

    loop {
        let batch_started = Instant::now();
        let deleted = sqlx::query(
            "DELETE FROM query_log WHERE rowid IN (SELECT rowid FROM query_log WHERE created_at < ? LIMIT 1000)",
        )
        .bind(&cutoff)
        .execute(pool)
        .await
        .map_err(db_err("Failed to delete old query logs"))?
        .rows_affected();
        if deleted == 0 {
            break;
        }
        total_deleted += deleted;
        tokio::time::sleep(retention_pause(batch_started.elapsed())).await;
    }

    let reclaimed_pages = reclaim_free_pages(pool).await.map_err(db_err(
        "Failed to give free pages back to the database file",
    ))?;

    info!(
        deleted = total_deleted,
        reclaimed_pages, days, "Old query logs deleted (batched)"
    );
    Ok(total_deleted)
}

/// `PRAGMA auto_vacuum` value of a database that can give pages back step by step.
const AUTO_VACUUM_INCREMENTAL: i64 = 2;

/// Pages given back per step: 8 MiB at SQLite's default 4 KiB page.
const RECLAIM_PAGES_PER_STEP: i64 = 2048;

/// Gives the free pages back to the file, whichever delete freed them, paced like the
/// deletes. A passive checkpoint follows each step, so the WAL holds one step's pages
/// rather than everything moved since the checkpoint job's last pass. A database
/// created before auto-vacuum was enabled cannot give pages back; it returns 0.
async fn reclaim_free_pages(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
        .fetch_one(pool)
        .await?;
    if auto_vacuum != AUTO_VACUUM_INCREMENTAL {
        return Ok(0);
    }

    let mut free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
        .fetch_one(pool)
        .await?;
    let mut reclaimed = 0;
    while free > 0 {
        let step_started = Instant::now();
        // Each result row of incremental_vacuum is one page moved; `execute` steps
        // through all of them.
        sqlx::query(&format!(
            "PRAGMA incremental_vacuum({RECLAIM_PAGES_PER_STEP})"
        ))
        .execute(pool)
        .await?;
        sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
            .execute(pool)
            .await?;
        let left: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(pool)
            .await?;
        if left >= free {
            break;
        }
        reclaimed += free - left;
        free = left;
        tokio::time::sleep(retention_pause(step_started.elapsed())).await;
    }
    Ok(reclaimed)
}

/// How long retention waits after a batch before taking the write lock again: at least
/// as long as the batch held it, so a large backlog on slow storage never keeps the
/// query-log writer, client tracking or sessions waiting out their busy timeout.
fn retention_pause(batch_elapsed: Duration) -> Duration {
    batch_elapsed.max(Duration::from_millis(50))
}

#[cfg(test)]
mod tests {
    use super::{retention_pause, MALWARE_FILTER};
    use ferrous_dns_domain::BlockSource;
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn quoted_names(sql: &str) -> BTreeSet<&str> {
        sql.split('\'').skip(1).step_by(2).collect()
    }

    #[test]
    fn sql_malware_lists_match_block_source_classification() {
        let expected: BTreeSet<&str> = BlockSource::ALL
            .into_iter()
            .filter(|s| s.is_malware())
            .map(|s| s.to_str())
            .collect();
        assert_eq!(quoted_names(MALWARE_FILTER), expected);

        let backfill =
            include_str!("../../../../../migrations/20260923000002_backfill_query_log_rollups.sql");
        let list_start = backfill
            .find("block_source IN (")
            .expect("backfill classifies malware");
        let list = &backfill[list_start..];
        let list = &list[..list.find(')').expect("closed list")];
        assert_eq!(quoted_names(list), expected);
    }

    #[test]
    fn retention_leaves_the_write_lock_free_for_at_least_as_long_as_a_batch_held_it() {
        assert_eq!(
            retention_pause(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        assert_eq!(
            retention_pause(Duration::from_millis(1)),
            Duration::from_millis(50)
        );
    }
}
