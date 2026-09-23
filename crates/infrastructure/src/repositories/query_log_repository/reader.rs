use super::helpers::{hours_ago_cutoff, row_to_query_log, seconds_ago_cutoff, window_start_bucket};
use super::rollup;
use chrono::Utc;
use ferrous_dns_application::ports::PagedQueryResult;
use ferrous_dns_domain::query_log::{ClientProtocol, DnssecStats, QueryCategory, QueryLogFilter};
use ferrous_dns_domain::{DomainError, QueryLog, QueryStats};
use sqlx::{Row, SqlitePool};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument};

/// SQL mirror of `BlockSource::is_malware`; the rollup backfill carries the same list.
const MALWARE_FILTER: &str = " AND q.block_source IN ('dns_tunneling', 'dns_rebinding', 'nxdomain_hijack', 'response_ip_filter', 'dga_detection')";

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

    let cutoff = hours_ago_cutoff(period_hours);
    let rows = sqlx::query(
        "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                q.cache_hit, q.cache_refresh, q.dnssec_status, q.dns64_synthesized, q.answers, q.upstream_server,
                q.upstream_pool, q.response_status, q.query_source, q.protocol, q.group_id, q.block_source,
                datetime(q.created_at) as created_at, c.hostname
         FROM query_log q
         LEFT JOIN clients c ON q.client_ip = c.ip_address
         WHERE q.created_at >= ?
           AND q.query_source = 'client'
         ORDER BY q.created_at DESC
         LIMIT ?",
    )
    .bind(cutoff)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch recent queries");
        DomainError::DatabaseError(e.to_string())
    })?;

    let entries: Vec<QueryLog> = rows.into_iter().filter_map(row_to_query_log).collect();
    debug!(count = entries.len(), "Recent queries fetched successfully");
    Ok(entries)
}

#[instrument(skip(pool))]
pub(super) async fn get_recent_paged(
    pool: &SqlitePool,
    limit: u32,
    offset: u32,
    period_hours: f32,
    cursor: Option<i64>,
    filter: &QueryLogFilter,
) -> Result<PagedQueryResult, DomainError> {
    debug!(
        limit,
        offset,
        period_hours,
        cursor,
        ?filter,
        "Fetching paginated queries"
    );

    let fetch_limit = limit as i64 + 1;
    let cutoff = hours_ago_cutoff(period_hours);
    let domain_pattern = filter
        .domain
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(|d| format!("%{d}%"));
    let client_pattern = filter
        .client
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(|c| format!("%{c}%"));

    // Each arm is a static SQL fragment — no user input is interpolated.
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
        " AND q.domain LIKE ?"
    } else {
        ""
    };
    let client_clause = if client_pattern.is_some() {
        " AND (q.client_ip LIKE ? OR c.hostname LIKE ?)"
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
    // The `"any"` sentinel matches any validated row; otherwise exact match on
    // the bound status string. Each arm is a static SQL fragment.
    let dnssec_clause = match filter.dnssec_status.as_deref() {
        Some("any") => " AND q.dnssec_status IS NOT NULL",
        Some(_) => " AND q.dnssec_status = ?",
        None => "",
    };
    // Static fragment (no bound param) so it doesn't disturb `bind_filters!`.
    let dns64_clause = match filter.dns64_synthesized {
        Some(true) => " AND q.dns64_synthesized = 1",
        Some(false) => " AND q.dns64_synthesized = 0",
        None => "",
    };
    // Closed enum, so each arm is a static fragment too — no bind needed.
    let protocol_clause = match filter.protocol {
        Some(ClientProtocol::Udp) => " AND q.protocol = 'udp'",
        Some(ClientProtocol::Tcp) => " AND q.protocol = 'tcp'",
        Some(ClientProtocol::Dot) => " AND q.protocol = 'dot'",
        Some(ClientProtocol::Doh) => " AND q.protocol = 'doh'",
        Some(ClientProtocol::Doq) => " AND q.protocol = 'doq'",
        None => "",
    };

    // Binds the conditional filter parameters in a fixed order.
    macro_rules! bind_filters {
        ($query:expr, $filter:expr) => {{
            let mut q = $query;
            if let Some(ref pat) = domain_pattern {
                q = q.bind(pat);
            }
            if let Some(ref pat) = client_pattern {
                q = q.bind(pat).bind(pat);
            }
            if let Some(ref rt) = $filter.record_type {
                q = q.bind(rt.as_str());
            }
            if let Some(ref up) = $filter.upstream {
                q = q.bind(up);
            }
            if let Some(ref status) = $filter.dnssec_status {
                if status != "any" {
                    q = q.bind(status.as_str());
                }
            }
            q
        }};
    }

    let (rows_result, filtered_count_result, total_count_result) = tokio::join!(
        async {
            if let Some(cursor_id) = cursor {
                let sql = format!(
                    "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                            q.cache_hit, q.cache_refresh, q.dnssec_status, q.dns64_synthesized, q.answers, q.upstream_server,
                            q.upstream_pool, q.response_status, q.query_source, q.protocol, q.group_id, q.block_source,
                            datetime(q.created_at) as created_at, c.hostname
                     FROM query_log q
                     LEFT JOIN clients c ON q.client_ip = c.ip_address
                     WHERE q.id < ?
                       AND q.query_source = 'client'
                       AND q.created_at >= ?
                       {domain_clause}{category_clause}{client_clause}{type_clause}{upstream_clause}{dnssec_clause}{dns64_clause}{protocol_clause}
                     ORDER BY q.id DESC
                     LIMIT ?"
                );
                let q = sqlx::query(&sql).bind(cursor_id).bind(&cutoff);
                let q = bind_filters!(q, filter);
                q.bind(fetch_limit).fetch_all(pool).await
            } else {
                let sql = format!(
                    "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                            q.cache_hit, q.cache_refresh, q.dnssec_status, q.dns64_synthesized, q.answers, q.upstream_server,
                            q.upstream_pool, q.response_status, q.query_source, q.protocol, q.group_id, q.block_source,
                            datetime(q.created_at) as created_at, c.hostname
                     FROM query_log q
                     LEFT JOIN clients c ON q.client_ip = c.ip_address
                     WHERE q.created_at >= ?
                       AND q.query_source = 'client'
                       {domain_clause}{category_clause}{client_clause}{type_clause}{upstream_clause}{dnssec_clause}{dns64_clause}{protocol_clause}
                     ORDER BY q.created_at DESC
                     LIMIT ? OFFSET ?"
                );
                let q = sqlx::query(&sql).bind(&cutoff);
                let q = bind_filters!(q, filter);
                q.bind(fetch_limit)
                    .bind(offset as i64)
                    .fetch_all(pool)
                    .await
            }
        },
        async {
            let count_sql = format!(
                "SELECT COUNT(*) as cnt FROM query_log q
                 LEFT JOIN clients c ON q.client_ip = c.ip_address
                 WHERE q.query_source = 'client' AND q.created_at >= ?{domain_clause}{category_clause}{client_clause}{type_clause}{upstream_clause}{dnssec_clause}{dns64_clause}{protocol_clause}"
            );
            let q = sqlx::query(&count_sql).bind(&cutoff);
            let q = bind_filters!(q, filter);
            q.fetch_one(pool).await
        },
        async {
            sqlx::query(
                "SELECT COUNT(*) as cnt FROM query_log q
                 WHERE q.query_source = 'client' AND q.created_at >= ?",
            )
            .bind(&cutoff)
            .fetch_one(pool)
            .await
        }
    );

    let rows = rows_result.map_err(|e| {
        error!(error = %e, "Failed to fetch paginated queries");
        DomainError::DatabaseError(e.to_string())
    })?;

    let records_filtered = filtered_count_result
        .map(|r| r.get::<i64, _>("cnt") as u64)
        .map_err(|e| {
            error!(error = %e, "Failed to count filtered queries");
            DomainError::DatabaseError(e.to_string())
        })?;

    let records_total = total_count_result
        .map(|r| r.get::<i64, _>("cnt") as u64)
        .map_err(|e| {
            error!(error = %e, "Failed to count total queries");
            DomainError::DatabaseError(e.to_string())
        })?;

    let mut rows = rows;
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

fn db_error(context: &'static str) -> impl FnOnce(sqlx::Error) -> DomainError {
    move |e| {
        error!(error = %e, "{context}");
        DomainError::DatabaseError(e.to_string())
    }
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

    let row = totals.map_err(db_error("Failed to fetch statistics"))?;
    let type_rows = type_rows.map_err(db_error("Failed to fetch type distribution"))?;
    let block_source_rows =
        block_source_rows.map_err(db_error("Failed to fetch block source statistics"))?;
    let upstream_rows = upstream_rows.map_err(db_error("Failed to fetch upstream statistics"))?;

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
    .map_err(db_error("Failed to fetch DNSSEC statistics"))?;

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
    .map_err(db_error("Failed to count queries"))?;

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
    .map_err(db_error("Failed to fetch cache statistics"))?;

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

#[instrument(skip(pool))]
pub(super) async fn get_top_blocked_domains(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<(String, u64)>, DomainError> {
    let cutoff = hours_ago_cutoff(period_hours);
    let rows = sqlx::query(
        "SELECT domain, COUNT(*) as count
         FROM query_log
         WHERE blocked = 1
           AND created_at >= ?
           AND query_source = 'client'
         GROUP BY domain
         ORDER BY count DESC
         LIMIT ?",
    )
    .bind(cutoff)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch top blocked domains");
        DomainError::DatabaseError(e.to_string())
    })?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let domain: String = r.get("domain");
            let count = r.get::<i64, _>("count") as u64;
            (domain, count)
        })
        .collect())
}

#[instrument(skip(pool))]
pub(super) async fn get_top_allowed_domains(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<(String, u64)>, DomainError> {
    let cutoff = hours_ago_cutoff(period_hours);
    let rows = sqlx::query(
        "SELECT domain, COUNT(*) as count
         FROM query_log
         WHERE blocked = 0
           AND created_at >= ?
           AND query_source = 'client'
         GROUP BY domain
         ORDER BY count DESC
         LIMIT ?",
    )
    .bind(cutoff)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch top allowed domains");
        DomainError::DatabaseError(e.to_string())
    })?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let domain: String = r.get("domain");
            let count = r.get::<i64, _>("count") as u64;
            (domain, count)
        })
        .collect())
}

#[instrument(skip(pool))]
pub(super) async fn get_distinct_recent_domains(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<(String, u64)>, DomainError> {
    let cutoff = hours_ago_cutoff(period_hours);
    let rows = sqlx::query(
        "SELECT domain, COUNT(*) as count
         FROM query_log
         WHERE created_at >= ?
           AND query_source = 'client'
         GROUP BY domain
         ORDER BY count DESC
         LIMIT ?",
    )
    .bind(cutoff)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch distinct recent domains");
        DomainError::DatabaseError(e.to_string())
    })?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let domain: String = r.get("domain");
            let count = r.get::<i64, _>("count") as u64;
            (domain, count)
        })
        .collect())
}

#[instrument(skip(pool))]
pub(super) async fn get_top_clients(
    pool: &SqlitePool,
    limit: u32,
    period_hours: f32,
) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
    let cutoff = hours_ago_cutoff(period_hours);
    let rows = sqlx::query(
        "SELECT q.client_ip, c.hostname, COUNT(*) as count
         FROM query_log q
         LEFT JOIN clients c ON q.client_ip = c.ip_address
         WHERE q.created_at >= ?
           AND q.query_source = 'client'
         GROUP BY q.client_ip
         ORDER BY count DESC
         LIMIT ?",
    )
    .bind(cutoff)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch top clients");
        DomainError::DatabaseError(e.to_string())
    })?;

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

pub(super) async fn delete_older_than(pool: &SqlitePool, days: u32) -> Result<u64, DomainError> {
    let cutoff_at = Utc::now() - chrono::Duration::days(days as i64);
    let cutoff = cutoff_at.format("%Y-%m-%d %H:%M:%S").to_string();
    let mut total_deleted: u64 = 0;

    loop {
        let result = sqlx::query(
            "DELETE FROM query_log WHERE rowid IN (SELECT rowid FROM query_log WHERE created_at < ? LIMIT 5000)",
        )
        .bind(&cutoff)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete old query logs");
            DomainError::DatabaseError(format!("Failed to delete old query logs: {}", e))
        })?;

        let deleted = result.rows_affected();
        if deleted == 0 {
            break;
        }
        total_deleted += deleted;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A bucket straddling the cutoff goes whole, so `days = 0` clears everything.
    rollup::prune_before(pool, cutoff_at.timestamp())
        .await
        .map_err(db_error("Failed to prune query log rollups"))?;

    info!(
        deleted = total_deleted,
        days, "Old query logs deleted (batched)"
    );
    Ok(total_deleted)
}

#[cfg(test)]
mod tests {
    use super::MALWARE_FILTER;
    use ferrous_dns_domain::BlockSource;
    use std::collections::BTreeSet;

    fn quoted_names(sql: &str) -> BTreeSet<&str> {
        sql.split('\'').skip(1).step_by(2).collect()
    }

    #[test]
    fn sql_malware_lists_match_block_source_classification() {
        let expected: BTreeSet<&str> = (0..=u8::MAX)
            .filter_map(BlockSource::from_u8)
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
}
