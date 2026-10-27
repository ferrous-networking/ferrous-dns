//! Differential test for the rollup-backed reads: top domains, distinct domains,
//! top clients, the Query Log total and the storage counts must equal the same
//! questions asked of the raw log, wherever the rollup coverage and the window edges
//! fall, whether the reference SQL or the hourly job filled the rollups, and after
//! retention cuts into a bucket.

use chrono::{Duration, Timelike, Utc};
use ferrous_dns_application::ports::{
    BlockedClientStatsRepository, PageAt, QueryLogRepository, QueryLogRollupRepository,
    QueryLogStorageRepository,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::QueryLogFilter;
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::SqlitePool;

#[path = "support/db.rs"]
mod db;

const DOMAINS: usize = 25;
const CLIENTS: u8 = 6;
const HOUR: i64 = 3_600;

fn repo(pool: &SqlitePool) -> SqliteQueryLogRepository {
    SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
        Default::default(),
    )
}

fn this_hour() -> i64 {
    let now = Utc::now().timestamp();
    now - now.rem_euclid(HOUR)
}

/// Raw rows spread over the last `hours`, at second 30 of a minute or on the hour,
/// where reads switch between raw rows and buckets. A window edge follows the clock
/// and never lands on a row; see `steady_clock`.
async fn seed(pool: &SqlitePool, rows: usize, hours: i64, rng: &mut fastrand::Rng) {
    let now = Utc::now();
    for _ in 0..rows {
        let minute = now - Duration::minutes(rng.i64(1..hours * 60));
        let at = if rng.u8(..10) == 0 {
            minute.with_minute(0).unwrap().with_second(0).unwrap()
        } else {
            minute.with_second(30).unwrap()
        };
        let source = if rng.u8(..5) == 0 {
            "internal"
        } else {
            "client"
        };
        sqlx::query(
            "INSERT INTO query_log (domain, record_type, client_ip, blocked, query_source, created_at)
             VALUES (?, 'A', ?, ?, ?, ?)",
        )
        .bind(format!("d{}.example", rng.usize(..DOMAINS)))
        .bind(format!("192.168.1.{}", rng.u8(1..=CLIENTS)))
        .bind(rng.u8(..4) == 0)
        .bind(source)
        .bind(at.format("%Y-%m-%d %H:%M:%S").to_string())
        .execute(pool)
        .await
        .unwrap();
    }
}

/// Rollups exactly as the writer and the hourly job keep them, every bucket held.
async fn rebuild_rollups(pool: &SqlitePool) {
    sqlx::raw_sql(concat!(
        "DELETE FROM query_log_minute; DELETE FROM query_log_minute_record_type;",
        "DELETE FROM query_log_minute_block_source; DELETE FROM query_log_minute_upstream;",
        "DELETE FROM query_log_hour_domain; DELETE FROM query_log_hour_client;",
        include_str!("../../../migrations/20260923000002_backfill_query_log_rollups.sql"),
        include_str!("support/hour_rollups.sql"),
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn set_state(pool: &SqlitePool, name: &str, value: i64) {
    sqlx::query("UPDATE query_log_rollup_state SET value = ? WHERE name = ?")
        .bind(value)
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
}

async fn state(pool: &SqlitePool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT value FROM query_log_rollup_state WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Sets the coverage and poisons every bucket outside it: a read that used one of
/// them would be off by a thousand.
async fn set_coverage(pool: &SqlitePool, hour_since: i64, hour_until: i64, minute_since: i64) {
    set_state(pool, "hour_since", hour_since).await;
    set_state(pool, "hour_until", hour_until).await;
    set_state(pool, "minute_since", minute_since).await;
    for table in ["query_log_hour_domain", "query_log_hour_client"] {
        sqlx::query(&format!(
            "UPDATE {table} SET count = count + 1000 WHERE bucket < ? OR bucket >= ?"
        ))
        .bind(hour_since)
        .bind(hour_until)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE query_log_minute SET total = total + 1000 WHERE bucket < ?")
        .bind(minute_since)
        .execute(pool)
        .await
        .unwrap();
}

/// Waits out the seconds around :30 and :00, so the raw reference and the repository
/// read the same cutoff second relative to the rows.
async fn steady_clock() {
    while matches!(Utc::now().second(), 25..=35 | 55..=59 | 0..=5) {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

fn cutoff(hours: f32) -> String {
    (Utc::now() - Duration::milliseconds((hours * 3_600_000.0) as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

async fn raw_counts(
    pool: &SqlitePool,
    column: &str,
    hours: f32,
    verdict: &str,
) -> Vec<(String, u64)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(&format!(
        "SELECT {column}, COUNT(*) FROM query_log
         WHERE query_source = 'client' AND created_at >= ?{verdict}
         GROUP BY {column}"
    ))
    .bind(cutoff(hours))
    .fetch_all(pool)
    .await
    .unwrap();
    sorted(rows.into_iter().map(|(k, n)| (k, n as u64)).collect())
}

async fn raw_scalar(pool: &SqlitePool, sql: &str, hours: f32) -> u64 {
    let n: i64 = sqlx::query_scalar(sql)
        .bind(cutoff(hours))
        .fetch_one(pool)
        .await
        .unwrap();
    n as u64
}

fn sorted(mut counts: Vec<(String, u64)>) -> Vec<(String, u64)> {
    counts.sort();
    counts
}

fn assert_ranked(list: &[(String, u64)], what: &str) {
    assert!(
        list.windows(2).all(|w| w[0].1 >= w[1].1),
        "{what} is not ranked by count: {list:?}"
    );
}

async fn assert_reads_match_raw(pool: &SqlitePool, hours: f32, label: &str) {
    steady_clock().await;
    let repo = repo(pool);
    let all = 1_000;

    for (verdict, sql_verdict, list) in [
        (
            "blocked",
            " AND blocked = 1",
            repo.get_top_blocked_domains(all, hours).await,
        ),
        (
            "allowed",
            " AND blocked = 0",
            repo.get_top_allowed_domains(all, hours).await,
        ),
        (
            "any",
            "",
            repo.get_distinct_recent_domains(all, hours).await,
        ),
    ] {
        let list = list.unwrap();
        assert_ranked(&list, verdict);
        assert_eq!(
            sorted(list),
            raw_counts(pool, "domain", hours, sql_verdict).await,
            "{label}: top {verdict} domains over {hours} h"
        );
    }

    assert_eq!(
        repo.count_distinct_domains(hours).await.unwrap(),
        raw_scalar(
            pool,
            "SELECT COUNT(DISTINCT domain) FROM query_log
             WHERE query_source = 'client' AND created_at >= ?",
            hours
        )
        .await,
        "{label}: distinct domains over {hours} h"
    );

    for (blocked_only, sql_verdict, list) in [
        (false, "", repo.get_top_clients(all, hours).await),
        (
            true,
            " AND blocked = 1",
            repo.get_top_blocked_clients(all, hours).await,
        ),
    ] {
        let list: Vec<(String, u64)> = list
            .unwrap()
            .into_iter()
            .map(|(ip, _, n)| (ip, n))
            .collect();
        assert_ranked(&list, "top clients");
        assert_eq!(
            sorted(list),
            raw_counts(pool, "client_ip", hours, sql_verdict).await,
            "{label}: top clients (blocked only: {blocked_only}) over {hours} h"
        );
    }

    let window_total = raw_scalar(
        pool,
        "SELECT COUNT(*) FROM query_log WHERE query_source = 'client' AND created_at >= ?",
        hours,
    )
    .await;
    let page = repo
        .get_recent_paged(1, PageAt::Offset(0), hours, &QueryLogFilter::default())
        .await
        .unwrap();
    assert_eq!(
        page.records_total, window_total,
        "{label}: Query Log total over {hours} h"
    );
    assert_eq!(
        page.records_filtered, window_total,
        "{label}: unfiltered count over {hours} h"
    );

    let storage = repo.get_storage(hours).await.unwrap();
    assert_eq!(
        storage.recent_queries, window_total,
        "{label}: recent queries over {hours} h"
    );
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM query_log WHERE query_source = 'client'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        storage.stored_queries, stored as u64,
        "{label}: stored queries"
    );
}

const WINDOWS: [f32; 6] = [0.25, 1.0, 5.5, 24.0, 47.9, 720.0];

#[tokio::test]
async fn rollup_reads_equal_raw_reads_wherever_the_coverage_falls() {
    let pool = db::migrated_pool().await;
    let mut rng = fastrand::Rng::with_seed(0x5eed_2027);
    seed(&pool, 3_000, 72, &mut rng).await;

    let hour = this_hour();
    let minute = Utc::now().timestamp() / 60 * 60;
    for (label, hour_since, hour_until, minute_since) in [
        ("every past hour held", 0, hour, 0),
        ("hours held through the next one", 0, hour + HOUR, 0),
        (
            "a middle stretch held",
            hour - 30 * HOUR,
            hour - 2 * HOUR,
            0,
        ),
        ("no hour held", hour, hour, minute - 90 * 60),
        ("minutes held from the next one", 0, hour, minute + 60),
    ] {
        rebuild_rollups(&pool).await;
        set_coverage(&pool, hour_since, hour_until, minute_since).await;
        for hours in WINDOWS {
            assert_reads_match_raw(&pool, hours, label).await;
        }
    }
}

#[tokio::test]
async fn the_hourly_job_fills_closed_hours_and_the_history_and_reads_stay_exact() {
    let pool = db::migrated_pool().await;
    let mut rng = fastrand::Rng::with_seed(0x5eed_2029);
    seed(&pool, 3_000, 72, &mut rng).await;
    rebuild_rollups(&pool).await;
    sqlx::raw_sql("DELETE FROM query_log_hour_domain; DELETE FROM query_log_hour_client;")
        .execute(&pool)
        .await
        .unwrap();
    // Where the migration leaves a log with history: nothing held, five hours ago as
    // the job's starting point, so it has both closed hours ahead and history behind.
    let start = this_hour() - 5 * HOUR;
    set_state(&pool, "hour_since", start).await;
    set_state(&pool, "hour_until", start).await;

    let repo = repo(&pool);
    let mut stored = 0;
    loop {
        let hours = repo.roll_up_hours(24).await.unwrap();
        if hours == 0 {
            break;
        }
        stored += hours;
    }

    // The last closed hour, unless it closed less than the job's lag ago.
    let until = state(&pool, "hour_until").await;
    assert!(
        until == this_hour() || until == this_hour() - HOUR,
        "hour_until {until} stopped short of the last closed hour"
    );
    let oldest: i64 = sqlx::query_scalar(
        "SELECT CAST(strftime('%s', MIN(created_at)) AS INTEGER) / 3600 * 3600
         FROM query_log WHERE query_source = 'client'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        state(&pool, "hour_since").await,
        oldest,
        "history not filled"
    );
    assert_eq!(stored as i64, (until - oldest) / HOUR);

    for hours in WINDOWS {
        assert_reads_match_raw(&pool, hours, "filled by the job").await;
    }
}

#[tokio::test]
async fn rollup_reads_stay_exact_after_retention_cuts_into_a_bucket() {
    let pool = db::migrated_pool().await;
    let mut rng = fastrand::Rng::with_seed(0x5eed_2028);
    // Ten days of rows; retention keeps three, so the oldest kept hour and minute are
    // cut in two and their rollup buckets go whole.
    seed(&pool, 3_000, 240, &mut rng).await;
    rebuild_rollups(&pool).await;
    set_coverage(&pool, 0, this_hour(), 0).await;

    steady_clock().await;
    let repo = repo(&pool);
    repo.delete_older_than(3).await.unwrap();
    for hours in [1.0, 24.0, 71.9, 72.0, 72.1, 240.0] {
        assert_reads_match_raw(&pool, hours, "after retention").await;
    }

    // The job must not fill the hour retention cut into, nor anything before it.
    let floor = state(&pool, "hour_floor").await;
    let since_before = state(&pool, "hour_since").await;
    assert_eq!(since_before, floor);
    while repo.roll_up_hours(24).await.unwrap() > 0 {}
    assert_eq!(state(&pool, "hour_since").await, floor);
    for hours in [72.0, 240.0] {
        assert_reads_match_raw(&pool, hours, "after retention and the job").await;
    }
}
