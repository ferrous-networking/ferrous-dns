//! Tests for DNSSEC aggregation (`get_dnssec_stats`) and the `dnssec_status`
//! filter on the paginated query log reader.

use ferrous_dns_application::ports::{PageAt, QueryLogRepository};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{DnssecStatus, DnssecStatusFilter, QueryLogFilter};
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;

#[path = "support/db.rs"]
mod db;

use db::migrated_pool;

async fn insert(pool: &sqlx::SqlitePool, dnssec_status: Option<&str>, query_source: &str) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, response_time_ms, dnssec_status, query_source)
         VALUES ('example.com', 'A', '192.168.1.1', 100, ?, ?)",
    )
    .bind(dnssec_status)
    .bind(query_source)
    .execute(pool)
    .await
    .unwrap();

    // Aggregates come from the rollups; rebuild them with the production backfill.
    sqlx::raw_sql(concat!(
        "DELETE FROM query_log_minute; DELETE FROM query_log_minute_record_type;",
        "DELETE FROM query_log_minute_block_source; DELETE FROM query_log_minute_upstream;",
        include_str!("../../../migrations/20260923000002_backfill_query_log_rollups.sql"),
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn seed(pool: &sqlx::SqlitePool) {
    for _ in 0..3 {
        insert(pool, Some("Secure"), "client").await;
    }
    for _ in 0..2 {
        insert(pool, Some("Insecure"), "client").await;
    }
    insert(pool, Some("Bogus"), "client").await;
    insert(pool, Some("Indeterminate"), "client").await;
    insert(pool, None, "client").await;
    insert(pool, None, "client").await;
    // The validator's own lookups must never count towards client stats.
    insert(pool, Some("Bogus"), "dnssec_validation").await;
}

fn repo(pool: &sqlx::SqlitePool) -> SqliteQueryLogRepository {
    SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
        Default::default(),
    )
}

#[tokio::test]
async fn dnssec_stats_counts_by_status_excluding_validator_lookups() {
    let pool = migrated_pool().await;
    seed(&pool).await;

    let stats = repo(&pool).get_dnssec_stats(24.0).await.unwrap();

    assert_eq!(
        stats.total, 9,
        "client rows only (dnssec_validation excluded)"
    );
    assert_eq!(stats.validated, 7, "non-null status among client rows");
    assert_eq!(stats.secure, 3);
    assert_eq!(stats.insecure, 2);
    assert_eq!(
        stats.bogus, 1,
        "the dnssec_validation Bogus row is excluded"
    );
    assert_eq!(stats.indeterminate, 1);
}

#[tokio::test]
async fn dnssec_stats_empty_is_all_zero() {
    let pool = migrated_pool().await;
    let stats = repo(&pool).get_dnssec_stats(24.0).await.unwrap();
    assert_eq!(stats.total, 0);
    assert_eq!(stats.validated, 0);
    assert_eq!(stats.secure, 0);
}

async fn count_with_filter(pool: &sqlx::SqlitePool, status: Option<DnssecStatusFilter>) -> u64 {
    let filter = QueryLogFilter {
        dnssec_status: status,
        ..Default::default()
    };
    repo(pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap()
        .records_filtered
}

#[tokio::test]
async fn dnssec_status_filter_any_matches_validated_rows() {
    let pool = migrated_pool().await;
    seed(&pool).await;
    // "any" → every client row with a non-null status.
    assert_eq!(
        count_with_filter(&pool, Some(DnssecStatusFilter::Any)).await,
        7
    );
}

#[tokio::test]
async fn dnssec_status_filter_exact_matches_one_status() {
    let pool = migrated_pool().await;
    seed(&pool).await;
    let exact = |status| Some(DnssecStatusFilter::Is(status));
    assert_eq!(
        count_with_filter(&pool, exact(DnssecStatus::Secure)).await,
        3
    );
    assert_eq!(
        count_with_filter(&pool, exact(DnssecStatus::Bogus)).await,
        1
    );
    // No filter → all client rows (validated or not).
    assert_eq!(count_with_filter(&pool, None).await, 9);
}
