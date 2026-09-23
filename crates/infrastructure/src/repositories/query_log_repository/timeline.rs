use super::helpers::window_start_bucket;
use ferrous_dns_application::ports::{TimeGranularity, TimelineBucket};
use ferrous_dns_domain::DomainError;
use sqlx::{Row, SqlitePool};
use tracing::{debug, error, instrument};

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
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[instrument(skip(pool))]
pub(super) async fn get_timeline(
    pool: &SqlitePool,
    period_hours: u32,
    granularity: TimeGranularity,
) -> Result<Vec<TimelineBucket>, DomainError> {
    let width = bucket_width_secs(granularity);
    let since = window_start_bucket(period_hours as f32);

    let rows = sqlx::query(
        "SELECT bucket - (bucket % ?) AS time_bucket,
                SUM(total) AS total,
                SUM(blocked) AS blocked,
                SUM(malware) AS malware
         FROM query_log_minute
         WHERE bucket >= ?
           AND query_source = 'client'
         GROUP BY time_bucket
         ORDER BY time_bucket ASC",
    )
    .bind(width)
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch timeline");
        DomainError::DatabaseError(e.to_string())
    })?;

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
                malware_detected: row.get::<i64, _>("malware") as u64,
            }
        })
        .collect();

    debug!(buckets = timeline.len(), "Timeline fetched");
    Ok(timeline)
}
