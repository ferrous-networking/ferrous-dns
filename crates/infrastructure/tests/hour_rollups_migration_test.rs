//! `20261027000001_create_query_log_hour_rollups`, run over a database migrated
//! to the schema before it and holding rows earlier releases wrote.

use chrono::Utc;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

const VERSION: i64 = 20261027000001;
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

async fn state(pool: &SqlitePool, name: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT {name} FROM query_log_rollup_state"))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn rows(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

fn hour_of(before: i64, after: i64) -> impl Fn(i64) -> bool {
    move |value| value == before / 3_600 * 3_600 || value == after / 3_600 * 3_600
}

#[tokio::test]
async fn test_an_existing_log_holds_no_hour_yet_and_its_oldest_minute_is_read_raw() {
    let pool = pool_before_the_migration().await;
    sqlx::raw_sql(
        "INSERT INTO query_log (domain, record_type, client_ip, query_source, created_at)
         VALUES ('a.example', 'A', '10.0.0.2', 'internal', '2026-10-19 23:00:00'),
                ('b.example', 'A', '10.0.0.2', 'client',   '2026-10-20 08:15:40'),
                ('c.example', 'A', '10.0.0.2', 'client',   '2026-10-26 21:59:59');",
    )
    .execute(&pool)
    .await
    .unwrap();

    let before = Utc::now().timestamp();
    MIGRATOR.run(&pool).await.unwrap();
    let after = Utc::now().timestamp();

    // 2026-10-20 08:16:00 UTC: the minute after the oldest client row, which
    // retention may have cut into. Internal rows never reach the rollups.
    assert_eq!(state(&pool, "minute_since").await, 1_792_484_160);
    // Nothing held: the job starts from the current hour, both ways.
    let since = state(&pool, "hour_since").await;
    assert!(hour_of(before, after)(since), "hour_since {since}");
    assert_eq!(state(&pool, "hour_until").await, since);
    assert_eq!(state(&pool, "hour_floor").await, 0);
    assert_eq!(rows(&pool, "query_log_hour_domain").await, 0, "no backfill");
    assert_eq!(rows(&pool, "query_log_hour_client").await, 0, "no backfill");
}

#[tokio::test]
async fn test_a_fresh_database_reads_every_minute_from_the_rollups() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();

    assert_eq!(state(&pool, "minute_since").await, 0);
}
