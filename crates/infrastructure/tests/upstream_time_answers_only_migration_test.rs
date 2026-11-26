//! `20261126000001_upstream_time_counts_answers_only`, run over a database
//! migrated to the schema before it and holding rows earlier releases wrote.

use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::borrow::Cow;

const VERSION: i64 = 20261126000001;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

async fn pool_before_the_migration() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let earlier = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < VERSION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    earlier.run(&pool).await.unwrap();
    pool
}

/// Seeds raw rows and the rollups the writer kept for them: an upstream answer,
/// a timeout and a SERVFAIL in one minute, a cache hit in the next.
async fn seed(pool: &SqlitePool) {
    sqlx::raw_sql(
        "INSERT INTO query_log (domain, record_type, client_ip, response_time_ms, cache_hit,
                                upstream_server, response_status, query_source, created_at)
         VALUES ('answered.example', 'A', '10.0.0.2', 20000,   0, 'dns.google', 'NOERROR',
                 'client', '2026-11-25 03:00:05'),
                ('timeout.example',  'A', '10.0.0.2', 9000000, 0, NULL,         'TIMEOUT',
                 'client', '2026-11-25 03:00:20'),
                ('servfail.example', 'A', '10.0.0.2', 6000000, 0, NULL,         'SERVFAIL',
                 'client', '2026-11-25 03:00:40'),
                ('cached.example',   'A', '10.0.0.2', 50,      1, NULL,         'NOERROR',
                 'client', '2026-11-25 03:01:10');",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260923000002_backfill_query_log_rollups.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn upstream_time_per_bucket(pool: &SqlitePool) -> Vec<(i64, i64, i64)> {
    sqlx::query(
        "SELECT bucket, upstream_timed, upstream_response_us_sum FROM query_log_minute
         WHERE query_source = 'client' ORDER BY bucket",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get(0), r.get(1), r.get(2)))
    .collect()
}

#[tokio::test]
async fn failed_queries_leave_the_upstream_time_of_their_minute() {
    let pool = pool_before_the_migration().await;
    seed(&pool).await;
    let before = upstream_time_per_bucket(&pool).await;
    assert_eq!(
        (before[0].1, before[0].2),
        (3, 15_020_000),
        "the backfill timed both failures as upstream answers"
    );

    MIGRATOR.run(&pool).await.unwrap();

    assert_eq!(
        upstream_time_per_bucket(&pool).await,
        vec![(before[0].0, 1, 20_000), (before[1].0, 0, 0)],
        "only the answer an upstream served is left"
    );
}

#[tokio::test]
async fn a_fresh_database_migrates_cleanly() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    assert!(upstream_time_per_bucket(&pool).await.is_empty());
}
