//! Differential test for the query-log rollups: whatever the writer maintains
//! incrementally, flush by flush, must equal the backfill migration replayed over
//! the raw rows it wrote. The backfill is the declarative reference for every
//! counter, so this pins the Rust aggregation and the SQL to one definition.

use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{BlockSource, QueryLog, QuerySource, RecordType};
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::sqlite::SqlitePoolOptions;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

const ROLLUP_TABLES: [&str; 4] = [
    "query_log_minute",
    "query_log_minute_record_type",
    "query_log_minute_block_source",
    "query_log_minute_upstream",
];

fn pick<T: Clone>(rng: &mut fastrand::Rng, items: &[T]) -> T {
    items[rng.usize(..items.len())].clone()
}

fn random_query(rng: &mut fastrand::Rng) -> QueryLog {
    let block_sources: Vec<BlockSource> = (0..=u8::MAX).filter_map(BlockSource::from_u8).collect();
    let blocked = rng.u8(..4) == 0;
    let upstream: Option<(Arc<str>, Arc<str>)> = pick(
        rng,
        &[
            None,
            Some(("pool1".into(), "dns.google".into())),
            Some(("pool1".into(), "1.1.1.1".into())),
            Some(("backup".into(), "9.9.9.9".into())),
        ],
    );
    QueryLog {
        id: None,
        domain: pick(rng, &["a.example", "b.example", "c.example"]).into(),
        record_type: pick(
            rng,
            &[
                RecordType::A,
                RecordType::AAAA,
                RecordType::HTTPS,
                RecordType::PTR,
            ],
        ),
        client_ip: IpAddr::from([192, 168, 1, rng.u8(1..5)]),
        client_hostname: None,
        blocked,
        // Mostly timed, as production always is; untimed rows exercise the NULL path.
        response_time_us: (rng.u8(..10) != 0).then(|| rng.u64(1..200_000)),
        cache_hit: rng.bool(),
        cache_refresh: rng.u8(..8) == 0,
        dnssec_status: pick(
            rng,
            &[
                None,
                Some("Secure"),
                Some("Insecure"),
                Some("Bogus"),
                Some("Indeterminate"),
                Some("Unknown"),
            ],
        ),
        dns64_synthesized: rng.u8(..8) == 0,
        answers: None,
        upstream_pool: upstream.as_ref().map(|(p, _)| Arc::clone(p)),
        upstream_server: upstream.map(|(_, s)| s),
        response_status: pick(
            rng,
            &[
                None,
                Some("NOERROR"),
                Some("NXDOMAIN"),
                Some("LOCAL_DNS"),
                Some("RATE_LIMITED"),
                Some("RATE_LIMITED_TC"),
                Some("BLOCKED"),
            ],
        ),
        timestamp: None,
        query_source: pick(
            rng,
            &[
                QuerySource::Client,
                QuerySource::Client,
                QuerySource::Internal,
                QuerySource::DnssecValidation,
            ],
        ),
        protocol: None,
        group_id: None,
        block_source: (rng.u8(..5) != 0).then(|| pick(rng, &block_sources)),
    }
}

async fn raw_row_count(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Rows in `a` missing from `b`, both directions, as a single count.
async fn symmetric_difference(pool: &sqlx::SqlitePool, a: &str, b: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT (SELECT COUNT(*) FROM (SELECT * FROM {a} EXCEPT SELECT * FROM {b}))
              + (SELECT COUNT(*) FROM (SELECT * FROM {b} EXCEPT SELECT * FROM {a}))"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn writer_rollups_equal_backfill_over_raw_rows() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();

    let cfg = DatabaseConfig {
        query_log_max_batch_size: 97,
        query_log_flush_interval_ms: 5,
        ..DatabaseConfig::default()
    };
    let repo = SqliteQueryLogRepository::new(pool.clone(), pool.clone(), pool.clone(), &cfg);

    // Several waves, each awaited, so buckets receive repeated upserts and the
    // ON CONFLICT accumulation path is exercised, not just first inserts.
    let mut rng = fastrand::Rng::with_seed(0x5eed_2026);
    let mut sent = 0i64;
    for _ in 0..8 {
        for _ in 0..250 {
            repo.log_query(&random_query(&mut rng)).await.unwrap();
            sent += 1;
        }
        for _ in 0..200 {
            if raw_row_count(&pool).await == sent {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            raw_row_count(&pool).await,
            sent,
            "writer did not flush in time"
        );
    }

    for table in ROLLUP_TABLES {
        sqlx::raw_sql(&format!(
            "CREATE TABLE writer_{table} AS SELECT * FROM {table}; DELETE FROM {table};"
        ))
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::raw_sql(include_str!(
        "../../../migrations/20260923000002_backfill_query_log_rollups.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    for table in ROLLUP_TABLES {
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(rows > 0, "{table}: seeded data must populate every rollup");
        assert_eq!(
            symmetric_difference(&pool, table, &format!("writer_{table}")).await,
            0,
            "{table}: writer and backfill disagree"
        );
    }
}
