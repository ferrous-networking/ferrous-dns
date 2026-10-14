use super::helpers::window_start_bucket;
use crate::repositories::{db_err, sql_ts};
use chrono::DateTime;
use ferrous_dns_application::ports::{TimeGranularity, TimelineBucket};
use ferrous_dns_domain::DomainError;
use sqlx::{Row, SqlitePool};
use tracing::{debug, instrument};

/// Every width divides a UTC day, so epoch-aligned buckets match wall-clock ones.
fn bucket_width_secs(granularity: TimeGranularity) -> i64 {
    match granularity {
        TimeGranularity::Minute => 60,
        TimeGranularity::TenMinutes => 600,
        TimeGranularity::QuarterHour => 900,
        TimeGranularity::Hour => 3_600,
        TimeGranularity::Day => 86_400,
    }
}

fn format_bucket(unix_secs: i64) -> String {
    sql_ts(DateTime::from_timestamp(unix_secs, 0).unwrap_or_default())
}

#[instrument(skip(pool))]
pub(super) async fn get_timeline(
    pool: &SqlitePool,
    period_hours: f32,
    granularity: TimeGranularity,
) -> Result<Vec<TimelineBucket>, DomainError> {
    let width = bucket_width_secs(granularity);
    let since = window_start_bucket(period_hours);

    // Forwarded comes from the upstream breakdown, the same source as the
    // summary's forwarded count.
    let rows = sqlx::query(
        "SELECT m.time_bucket, m.total, m.blocked, m.cached, m.malware,
                COALESCE(u.forwarded, 0) AS forwarded
         FROM (SELECT bucket - (bucket % ?) AS time_bucket,
                      SUM(total) AS total,
                      SUM(blocked) AS blocked,
                      SUM(cache_hits + local_dns) AS cached,
                      SUM(malware) AS malware
               FROM query_log_minute
               WHERE bucket >= ?
                 AND query_source = 'client'
               GROUP BY time_bucket) m
         LEFT JOIN (SELECT bucket - (bucket % ?) AS time_bucket,
                           SUM(count) AS forwarded
                    FROM query_log_minute_upstream
                    WHERE bucket >= ?
                    GROUP BY time_bucket) u
           ON u.time_bucket = m.time_bucket
         ORDER BY m.time_bucket ASC",
    )
    .bind(width)
    .bind(since)
    .bind(width)
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(db_err("Failed to fetch timeline"))?;

    let timeline: Vec<TimelineBucket> = rows
        .into_iter()
        .map(|row| {
            let total = row.get::<i64, _>("total") as u64;
            let blocked = row.get::<i64, _>("blocked") as u64;
            TimelineBucket {
                timestamp: format_bucket(row.get("time_bucket")),
                total,
                blocked,
                unblocked: total.saturating_sub(blocked),
                cached: row.get::<i64, _>("cached") as u64,
                forwarded: row.get::<i64, _>("forwarded") as u64,
                malware_detected: row.get::<i64, _>("malware") as u64,
            }
        })
        .collect();

    debug!(buckets = timeline.len(), "Timeline fetched");
    Ok(timeline)
}
