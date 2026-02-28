use super::helpers::{granularity_to_sql, hours_ago_cutoff};
use dashmap::DashMap;
use ferrous_dns_application::ports::{TimeGranularity, TimelineBucket};
use ferrous_dns_domain::DomainError;
use sqlx::{Row, SqlitePool};
use std::time::Instant;
use tracing::{debug, error, instrument};

pub(super) struct TimelineCache {
    cache: DashMap<(u32, &'static str), (Vec<TimelineBucket>, Instant)>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl TimelineCache {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }
}

fn build_timeline_sql(bucket_expr: &'static str) -> String {
    format!(
        "SELECT {bucket_expr} as time_bucket, \
         COUNT(*) as total, \
         SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked, \
         SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END) as unblocked \
         FROM query_log \
         WHERE created_at >= ? \
           AND query_source = 'client' \
         GROUP BY time_bucket \
         ORDER BY time_bucket ASC"
    )
}

#[instrument(skip(pool, timeline_cache))]
pub(super) async fn get_timeline(
    pool: &SqlitePool,
    timeline_cache: &TimelineCache,
    period_hours: u32,
    granularity: TimeGranularity,
) -> Result<Vec<TimelineBucket>, DomainError> {
    const TIMELINE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

    let bucket_expr = granularity_to_sql(granularity);
    let cache_key = (period_hours, bucket_expr);

    if let Some(entry) = timeline_cache.cache.get(&cache_key) {
        let (ref cached_buckets, cached_at) = *entry;
        if cached_at.elapsed() < TIMELINE_CACHE_TTL {
            debug!(period_hours, "Timeline served from cache");
            return Ok(cached_buckets.clone());
        }
    }

    let _lock = timeline_cache.refresh_lock.lock().await;

    if let Some(entry) = timeline_cache.cache.get(&cache_key) {
        let (ref cached_buckets, cached_at) = *entry;
        if cached_at.elapsed() < TIMELINE_CACHE_TTL {
            return Ok(cached_buckets.clone());
        }
    }

    debug!(period_hours, "Fetching query timeline");

    let sql = build_timeline_sql(bucket_expr);
    let cutoff = hours_ago_cutoff(period_hours as f32);

    let rows = sqlx::query(&sql)
        .bind(cutoff)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch timeline");
            DomainError::DatabaseError(e.to_string())
        })?;

    let timeline: Vec<TimelineBucket> = rows
        .into_iter()
        .map(|row| TimelineBucket {
            timestamp: row.get("time_bucket"),
            total: row.get::<i64, _>("total") as u64,
            blocked: row.get::<i64, _>("blocked") as u64,
            unblocked: row.get::<i64, _>("unblocked") as u64,
        })
        .collect();

    debug!(buckets = timeline.len(), "Timeline fetched successfully");
    timeline_cache
        .cache
        .insert(cache_key, (timeline.clone(), Instant::now()));
    Ok(timeline)
}
