//! The hourly rollup job against a live writer and a clock that steps backwards.

use chrono::{Duration, Utc};
use ferrous_dns_application::ports::{QueryLogRepository, QueryLogRollupRepository};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::SqlitePool;

#[path = "support/db.rs"]
mod db;
#[path = "support/rollups.rs"]
mod rollups;

use rollups::{repo, rollup_state as state, set_rollup_state as set_state};

const HOUR: i64 = 3_600;

fn this_hour() -> i64 {
    let now = Utc::now().timestamp();
    now - now.rem_euclid(HOUR)
}

async fn insert_client_row(pool: &SqlitePool, domain: &str, created_at: &str) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, query_source, created_at)
         VALUES (?, 'A', '10.0.0.1', 0, 'client', ?)",
    )
    .bind(domain)
    .bind(created_at)
    .execute(pool)
    .await
    .unwrap();
}

fn sql_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[tokio::test]
async fn test_roll_up_waits_for_the_query_log_writer_instead_of_failing_busy() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig::default();
    let write = create_write_pool(&url, &cfg).await.unwrap();
    let query_log = create_query_log_pool(&url, &cfg).await.unwrap();
    let read = create_read_pool(&url, &cfg).await.unwrap();
    // A client row an hour ago: the job's next hour is the one before `hour_since`.
    let an_hour_ago = (Utc::now() - Duration::hours(1))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    insert_client_row(&write, "a.example", &an_hour_ago).await;
    let repo = SqliteQueryLogRepository::new(
        write.clone(),
        query_log.clone(),
        read.clone(),
        &cfg,
        Default::default(),
    );

    // The query-log writer holds the write lock for a second, as a flush does.
    let mut writer = query_log.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        sqlx::query("COMMIT").execute(&mut *writer).await.unwrap();
    });

    let result = repo.roll_up_hours(1).await;
    release.await.unwrap();
    assert!(
        matches!(result, Ok(1)),
        "the job must wait out the writer's lock (busy timeout 30 s), got {result:?}"
    );
}

/// What the job leaves after running on a clock two hours fast: hours the real clock
/// has not reached yet are held.
async fn held_by_a_fast_clock(pool: &SqlitePool) {
    set_state(pool, "hour_since", this_hour() - 2 * HOUR).await;
    set_state(pool, "hour_until", this_hour() + 2 * HOUR).await;
    for hour in [this_hour(), this_hour() + HOUR] {
        sqlx::query(
            "INSERT INTO query_log_hour_domain (bucket, domain, blocked, count)
             VALUES (?, 'ahead.example', 0, 1)",
        )
        .bind(hour)
        .execute(pool)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn test_rows_logged_after_the_clock_steps_back_into_a_held_hour_are_counted() {
    let pool = db::migrated_pool().await;
    held_by_a_fast_clock(&pool).await;

    // The clock is corrected; the writer logs a query now.
    insert_client_row(&pool, "late.example", &sql_now()).await;

    let repo = repo(&pool);
    assert_eq!(
        repo.get_top_allowed_domains(10, 24.0).await.unwrap(),
        vec![("late.example".to_string(), 1)],
        "top allowed domains"
    );
    assert_eq!(repo.count_distinct_domains(24.0).await.unwrap(), 1);
    assert_eq!(repo.get_top_clients(10, 24.0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_roll_up_gives_back_the_hours_the_clock_has_not_closed() {
    let pool = db::migrated_pool().await;
    held_by_a_fast_clock(&pool).await;

    repo(&pool).roll_up_hours(1).await.unwrap();

    let until = state(&pool, "hour_until").await;
    assert!(
        until == this_hour() || until == this_hour() - HOUR,
        "hour_until {until} still holds hours the clock has not closed"
    );
    let ahead: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM query_log_hour_domain WHERE bucket >= ?")
            .bind(until)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ahead, 0, "buckets past hour_until were left behind");
}
