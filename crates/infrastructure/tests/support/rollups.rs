//! The query-log rollups rebuilt from raw rows, and their coverage state, for tests
//! that seed `query_log` directly instead of going through the writer and the job.

#![allow(dead_code)]

use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::SqlitePool;

/// Clears every rollup, refills it from the raw rows with the production backfill and
/// the hourly reference, and marks every minute and every past hour held.
pub const REBUILD_ROLLUPS: &str = concat!(
    include_str!("clear_rollups.sql"),
    include_str!("../../../../migrations/20260923000002_backfill_query_log_rollups.sql"),
    include_str!("hour_rollups.sql"),
    include_str!("hold_rollups.sql"),
);

pub async fn rebuild_rollups(pool: &SqlitePool) {
    sqlx::raw_sql(REBUILD_ROLLUPS).execute(pool).await.unwrap();
}

/// A repository whose three pools are `pool`.
pub fn repo(pool: &SqlitePool) -> SqliteQueryLogRepository {
    SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
        Default::default(),
    )
}

/// One column of `query_log_rollup_state`: `minute_since`, `hour_since`, `hour_until`
/// or `hour_floor`.
pub async fn rollup_state(pool: &SqlitePool, column: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT {column} FROM query_log_rollup_state"))
        .fetch_one(pool)
        .await
        .unwrap()
}

pub async fn set_rollup_state(pool: &SqlitePool, column: &str, value: i64) {
    sqlx::query(&format!("UPDATE query_log_rollup_state SET {column} = ?"))
        .bind(value)
        .execute(pool)
        .await
        .unwrap();
}
