use super::helpers::{
    days_ago_cutoff, get_uptime, hours_ago_cutoff, row_to_query_log, seconds_ago_cutoff,
};
use ferrous_dns_domain::{DomainError, QueryLog, QueryStats};
use sqlx::{Row, SqlitePool};
use std::time::Duration;
use tracing::{debug, error, info, instrument};

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
                q.cache_hit, q.cache_refresh, q.dnssec_status, q.upstream_server,
                q.upstream_pool, q.response_status, q.query_source, q.group_id, q.block_source,
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
) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError> {
    debug!(
        limit,
        offset, period_hours, cursor, "Fetching paginated queries"
    );

    let fetch_limit = limit as i64 + 1;
    let cutoff = hours_ago_cutoff(period_hours);

    let rows = if let Some(cursor_id) = cursor {
        sqlx::query(
            "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                    q.cache_hit, q.cache_refresh, q.dnssec_status, q.upstream_server,
                    q.upstream_pool, q.response_status, q.query_source, q.group_id, q.block_source,
                    datetime(q.created_at) as created_at, c.hostname
             FROM query_log q
             LEFT JOIN clients c ON q.client_ip = c.ip_address
             WHERE q.id < ?
               AND q.query_source = 'client'
               AND q.created_at >= ?
             ORDER BY q.id DESC
             LIMIT ?",
        )
        .bind(cursor_id)
        .bind(&cutoff)
        .bind(fetch_limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query(
            "SELECT q.id, q.domain, q.record_type, q.client_ip, q.blocked, q.response_time_ms,
                    q.cache_hit, q.cache_refresh, q.dnssec_status, q.upstream_server,
                    q.upstream_pool, q.response_status, q.query_source, q.group_id, q.block_source,
                    datetime(q.created_at) as created_at, c.hostname
             FROM query_log q
             LEFT JOIN clients c ON q.client_ip = c.ip_address
             WHERE q.created_at >= ?
               AND q.query_source = 'client'
             ORDER BY q.created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(&cutoff)
        .bind(fetch_limit)
        .bind(offset as i64)
        .fetch_all(pool)
        .await
    }
    .map_err(|e| {
        error!(error = %e, "Failed to fetch paginated queries");
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

    let estimated_total = if has_more {
        offset as u64 + limit as u64 + 1
    } else {
        offset as u64 + entries.len() as u64
    };

    debug!(
        count = entries.len(),
        estimated_total, next_cursor, "Paginated queries fetched"
    );
    Ok((entries, estimated_total, next_cursor))
}

#[instrument(skip(pool))]
pub(super) async fn get_stats(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<QueryStats, DomainError> {
    debug!(period_hours, "Fetching query statistics");

    let cutoff = hours_ago_cutoff(period_hours);

    let (row_result, type_rows_result, block_source_rows_result, upstream_rows_result) =
        tokio::join!(
            sqlx::query(
                "SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END) as cache_hits,
                    AVG(response_time_ms) as avg_time,
                    AVG(CASE WHEN cache_hit = 1 THEN response_time_ms END) as avg_cache_time,
                    AVG(CASE WHEN cache_hit = 0 AND blocked = 0 AND response_status != 'LOCAL_DNS' THEN response_time_ms END) as avg_upstream_time,
                    SUM(CASE WHEN response_status = 'LOCAL_DNS' THEN 1 ELSE 0 END) as local_dns_count
                 FROM query_log
                 WHERE response_time_ms IS NOT NULL
                   AND created_at >= ?
                   AND query_source = 'client'",
            )
            .bind(&cutoff)
            .fetch_one(pool),
            sqlx::query(
                "SELECT record_type, COUNT(*) as count
                 FROM query_log
                 WHERE created_at >= ?
                   AND query_source = 'client'
                 GROUP BY record_type",
            )
            .bind(&cutoff)
            .fetch_all(pool),
            sqlx::query(
                "SELECT block_source, COUNT(*) as count
                 FROM query_log
                 WHERE blocked = 1
                   AND block_source IS NOT NULL
                   AND response_time_ms IS NOT NULL
                   AND created_at >= ?
                   AND query_source = 'client'
                 GROUP BY block_source",
            )
            .bind(&cutoff)
            .fetch_all(pool),
            sqlx::query(
                "SELECT
                    COALESCE(upstream_pool, 'unknown') as pool,
                    COALESCE(upstream_server, 'unknown') as server,
                    COUNT(*) as count
                 FROM query_log
                 WHERE cache_hit = 0 AND blocked = 0
                   AND (response_status IS NULL OR response_status != 'LOCAL_DNS')
                   AND response_time_ms IS NOT NULL
                   AND created_at >= ?
                   AND query_source = 'client'
                 GROUP BY upstream_pool, upstream_server",
            )
            .bind(&cutoff)
            .fetch_all(pool),
        );

    let row = row_result.map_err(|e| {
        error!(error = %e, "Failed to fetch statistics");
        DomainError::DatabaseError(e.to_string())
    })?;
    let type_rows = type_rows_result.map_err(|e| {
        error!(error = %e, "Failed to fetch type distribution");
        DomainError::DatabaseError(e.to_string())
    })?;
    let block_source_rows = block_source_rows_result.map_err(|e| {
        error!(error = %e, "Failed to fetch block source statistics");
        DomainError::DatabaseError(e.to_string())
    })?;
    let upstream_rows = upstream_rows_result.map_err(|e| {
        error!(error = %e, "Failed to fetch upstream statistics");
        DomainError::DatabaseError(e.to_string())
    })?;

    let total = row.get::<i64, _>("total") as u64;
    let cache_hits = row.get::<i64, _>("cache_hits") as u64;
    let cache_hit_rate = if total > 0 {
        (cache_hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let mut queries_by_type = std::collections::HashMap::new();
    for type_row in type_rows {
        let type_str: String = type_row.get("record_type");
        let count: i64 = type_row.get("count");
        if let Ok(record_type) = type_str.parse::<ferrous_dns_domain::RecordType>() {
            queries_by_type.insert(record_type, count as u64);
        }
    }

    let mut source_stats = std::collections::HashMap::new();
    source_stats.insert("cache".to_string(), cache_hits);
    source_stats.insert(
        "local_dns".to_string(),
        row.get::<i64, _>("local_dns_count") as u64,
    );
    for upstream_row in upstream_rows {
        let pool: String = upstream_row.get("pool");
        let server: String = upstream_row.get("server");
        let count = upstream_row.get::<i64, _>("count") as u64;
        if count > 0 {
            source_stats.insert(format!("{pool}:{server}"), count);
        }
    }
    for block_row in block_source_rows {
        let key: String = block_row.get("block_source");
        let count = block_row.get::<i64, _>("count") as u64;
        if count > 0 {
            source_stats.insert(key, count);
        }
    }

    let stats = QueryStats {
        queries_total: total,
        queries_blocked: row.get::<i64, _>("blocked") as u64,
        unique_clients: 0,
        uptime_seconds: get_uptime(),
        cache_hit_rate,
        avg_query_time_ms: row.get::<Option<f64>, _>("avg_time").unwrap_or(0.0),
        avg_cache_time_ms: row.get::<Option<f64>, _>("avg_cache_time").unwrap_or(0.0),
        avg_upstream_time_ms: row
            .get::<Option<f64>, _>("avg_upstream_time")
            .unwrap_or(0.0),
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
pub(super) async fn count_queries_since(
    pool: &SqlitePool,
    seconds_ago: i64,
) -> Result<u64, DomainError> {
    let cutoff = seconds_ago_cutoff(seconds_ago);
    let row = sqlx::query(
        "SELECT COUNT(*) as count FROM query_log WHERE query_source = 'client' AND created_at >= ?",
    )
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to count queries");
        DomainError::DatabaseError(e.to_string())
    })?;

    Ok(row.get::<i64, _>("count") as u64)
}

#[instrument(skip(pool))]
pub(super) async fn get_cache_stats(
    pool: &SqlitePool,
    period_hours: f32,
) -> Result<ferrous_dns_application::ports::CacheStats, DomainError> {
    debug!(period_hours, "Fetching cache statistics");

    let cutoff = hours_ago_cutoff(period_hours);
    let row = sqlx::query(
        "SELECT
            SUM(CASE WHEN query_source = 'client' THEN 1 ELSE 0 END) as total_queries,
            SUM(CASE WHEN cache_hit = 1 AND cache_refresh = 0 AND query_source = 'client' THEN 1 ELSE 0 END) as hits,
            SUM(CASE WHEN cache_refresh = 1 THEN 1 ELSE 0 END) as refreshes,
            SUM(CASE WHEN cache_hit = 0 AND cache_refresh = 0 AND blocked = 0 AND query_source = 'client' THEN 1 ELSE 0 END) as misses
         FROM query_log
         WHERE created_at >= ?",
    )
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch cache statistics");
        DomainError::DatabaseError(e.to_string())
    })?;

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

pub(super) async fn delete_older_than(pool: &SqlitePool, days: u32) -> Result<u64, DomainError> {
    let cutoff = days_ago_cutoff(days);
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

    info!(
        deleted = total_deleted,
        days, "Old query logs deleted (batched)"
    );
    Ok(total_deleted)
}
