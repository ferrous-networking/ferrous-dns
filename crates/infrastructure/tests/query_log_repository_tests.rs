use ferrous_dns_application::ports::{PageAt, QueryLogRepository, TimeGranularity};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{
    ClientProtocol, QueryCategory, QueryLog, QueryLogFilter, QuerySource, RecordType,
};
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[path = "support/db.rs"]
mod db;

use db::migrated_pool;

const ROLLUP_BACKFILL: &str =
    include_str!("../../../migrations/20260923000002_backfill_query_log_rollups.sql");

fn repo(pool: &SqlitePool) -> SqliteQueryLogRepository {
    repo_with(pool, &DatabaseConfig::default())
}

fn repo_with(pool: &SqlitePool, cfg: &DatabaseConfig) -> SqliteQueryLogRepository {
    SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        cfg,
        Default::default(),
    )
}

/// Rebuilds the rollups from the raw rows with the production backfill, which
/// `query_log_rollup_test` proves equal to what the writer maintains.
async fn rebuild_rollups(pool: &SqlitePool) {
    sqlx::raw_sql(
        "DELETE FROM query_log_minute;
         DELETE FROM query_log_minute_record_type;
         DELETE FROM query_log_minute_block_source;
         DELETE FROM query_log_minute_upstream;",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(ROLLUP_BACKFILL).execute(pool).await.unwrap();
}

/// One raw `query_log` row; `created_at: None` stamps it with the current time.
#[derive(Clone, Copy)]
struct Row<'a> {
    domain: &'a str,
    client_ip: &'a str,
    record_type: &'a str,
    blocked: bool,
    cache_hit: bool,
    block_source: Option<&'a str>,
    response_status: Option<&'a str>,
    upstream_server: Option<&'a str>,
    upstream_pool: Option<&'a str>,
    query_source: &'a str,
    dns64_synthesized: bool,
    answers: Option<&'a str>,
    protocol: Option<&'a str>,
    created_at: Option<&'a str>,
}

impl Default for Row<'_> {
    fn default() -> Self {
        Self {
            domain: "example.com",
            client_ip: "192.168.1.1",
            record_type: "A",
            blocked: false,
            cache_hit: false,
            block_source: None,
            response_status: None,
            upstream_server: None,
            upstream_pool: None,
            query_source: "client",
            dns64_synthesized: false,
            answers: None,
            protocol: None,
            created_at: None,
        }
    }
}

async fn insert(pool: &SqlitePool, row: Row<'_>) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit,
                                block_source, response_status, upstream_server, upstream_pool,
                                query_source, dns64_synthesized, answers, protocol, created_at)
         VALUES (?, ?, ?, ?, 100, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))",
    )
    .bind(row.domain)
    .bind(row.record_type)
    .bind(row.client_ip)
    .bind(row.blocked)
    .bind(row.cache_hit)
    .bind(row.block_source)
    .bind(row.response_status)
    .bind(row.upstream_server)
    .bind(row.upstream_pool)
    .bind(row.query_source)
    .bind(row.dns64_synthesized)
    .bind(row.answers)
    .bind(row.protocol)
    .bind(row.created_at)
    .execute(pool)
    .await
    .unwrap();
}

/// Inserts a row for the rollup-backed stats; upstream-answered rows carry `pool1:dns.google`.
async fn insert_log(
    pool: &SqlitePool,
    cache_hit: bool,
    blocked: bool,
    block_source: Option<&str>,
    query_source: &str,
    created_at: Option<&str>,
) {
    let upstream_answered = !cache_hit && !blocked;
    insert(
        pool,
        Row {
            cache_hit,
            blocked,
            block_source,
            query_source,
            created_at,
            upstream_server: upstream_answered.then_some("dns.google"),
            upstream_pool: upstream_answered.then_some("pool1"),
            ..Row::default()
        },
    )
    .await;
    rebuild_rollups(pool).await;
}

async fn insert_client(pool: &SqlitePool, ip: &str, hostname: &str) {
    sqlx::query("INSERT INTO clients (ip_address, hostname) VALUES (?, ?)")
        .bind(ip)
        .bind(hostname)
        .execute(pool)
        .await
        .unwrap();
}

async fn page(pool: &SqlitePool, limit: u32, filter: &QueryLogFilter) -> Vec<QueryLog> {
    repo(pool)
        .get_recent_paged(limit, PageAt::Offset(0), 24.0, filter)
        .await
        .unwrap()
        .queries
}

fn domains(queries: &[QueryLog]) -> BTreeSet<&str> {
    queries.iter().map(|q| q.domain.as_ref()).collect()
}

fn no_filter() -> QueryLogFilter {
    QueryLogFilter::default()
}

fn category_filter(category: QueryCategory) -> QueryLogFilter {
    QueryLogFilter {
        category: Some(category),
        ..Default::default()
    }
}

/// Polls until the batched writer has persisted at least one row.
async fn wait_for_flush(pool: &SqlitePool) -> bool {
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(pool)
            .await
            .unwrap();
        if rows > 0 {
            return true;
        }
    }
    false
}

fn client_query(domain: &str, protocol: Option<ClientProtocol>) -> QueryLog {
    QueryLog {
        id: None,
        domain: domain.into(),
        record_type: RecordType::A,
        client_ip: "10.0.0.1".parse().unwrap(),
        client_hostname: None,
        blocked: false,
        response_time_us: Some(100),
        cache_hit: false,
        cache_refresh: false,
        dnssec_status: None,
        dns64_synthesized: false,
        answers: None,
        upstream_server: None,
        upstream_pool: None,
        response_status: Some("NOERROR"),
        timestamp: None,
        query_source: QuerySource::Client,
        protocol,
        group_id: None,
        block_source: None,
    }
}

#[tokio::test]
async fn test_get_stats_empty() {
    let pool = migrated_pool().await;

    let stats = repo(&pool).get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 0);
    assert_eq!(stats.queries_blocked, 0);
    assert_eq!(stats.source_stats.get("cache"), Some(&0));
    assert_eq!(stats.source_stats.get("pool1:dns.google"), None);
    assert_eq!(stats.source_stats.get("local_dns"), Some(&0));
    assert_eq!(stats.source_stats.get("blocklist"), None);
    assert_eq!(stats.source_stats.get("managed_domain"), None);
    assert_eq!(stats.source_stats.get("regex_filter"), None);
    assert_eq!(stats.source_stats.get("cname_cloaking"), None);
}

#[tokio::test]
async fn test_get_stats_uptime_counts_from_repository_creation() {
    let pool = migrated_pool().await;

    // The repository is built at startup, so the clock must already be
    // running when the first stats request arrives.
    let started = repo(&pool);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stats = started.get_stats(24.0).await.unwrap();
    assert!(
        stats.uptime_seconds >= 1,
        "uptime must count from startup, not from the first stats request; got {}",
        stats.uptime_seconds
    );

    // A fresh instance stands for a restarted process: it starts from zero.
    let stats = repo(&pool).get_stats(24.0).await.unwrap();
    assert_eq!(
        stats.uptime_seconds, 0,
        "a restarted server must not inherit the previous uptime"
    );
}

#[tokio::test]
async fn test_get_stats_cache_hits_count() {
    let pool = migrated_pool().await;

    for _ in 0..3 {
        insert_log(&pool, true, false, None, "client", None).await;
    }
    for _ in 0..2 {
        insert_log(&pool, false, false, None, "client", None).await;
    }

    let stats = repo(&pool).get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 5);
    assert_eq!(stats.source_stats.get("cache"), Some(&3));
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&2));
    assert_eq!(stats.queries_blocked, 0);
}

#[tokio::test]
async fn test_get_stats_blocklist_breakdown() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, false, true, Some("managed_domain"), "client", None).await;
    for _ in 0..3 {
        insert_log(&pool, false, true, Some("regex_filter"), "client", None).await;
    }

    let stats = repo(&pool).get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 6);
    assert_eq!(stats.source_stats.get("blocklist"), Some(&2));
    assert_eq!(stats.source_stats.get("managed_domain"), Some(&1));
    assert_eq!(stats.source_stats.get("regex_filter"), Some(&3));
    assert_eq!(stats.source_stats.get("cname_cloaking"), None);
}

#[tokio::test]
async fn test_get_stats_cname_cloaking_breakdown() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, true, Some("cname_cloaking"), "client", None).await;
    insert_log(&pool, false, true, Some("cname_cloaking"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;

    let stats = repo(&pool).get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 3);
    assert_eq!(stats.source_stats.get("cname_cloaking"), Some(&2));
    assert_eq!(stats.source_stats.get("blocklist"), Some(&1));
}

#[tokio::test]
async fn test_get_stats_excludes_internal_query_source() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(&pool, false, false, None, "internal", None).await;
    insert_log(&pool, true, false, None, "dnssec_validation", None).await;

    let stats = repo(&pool).get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&1));
    assert_eq!(stats.source_stats.get("cache"), Some(&0));
}

#[tokio::test]
async fn test_get_stats_period_filter() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(
        &pool,
        false,
        false,
        None,
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;

    let stats = repo(&pool).get_stats(1.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&1));
}

#[tokio::test]
async fn test_unbounded_period_covers_all_history_instead_of_panicking() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(
        &pool,
        false,
        true,
        Some("blocklist"),
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;

    // The Pi-hole API forwards `?from=` floats unclamped.
    let repo = repo(&pool);
    assert_eq!(repo.get_stats(f32::MAX).await.unwrap().queries_total, 2);
    assert_eq!(
        repo.get_top_blocked_domains(10, f32::MAX).await.unwrap(),
        vec![("example.com".to_string(), 1)]
    );
}

#[tokio::test]
async fn test_get_timeline_returns_buckets() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, true, false, None, "internal", None).await;

    let buckets = repo(&pool)
        .get_timeline(24.0, TimeGranularity::Hour)
        .await
        .unwrap();

    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].total, 2);
    assert_eq!(buckets[0].blocked, 1);
    assert_eq!(buckets[0].unblocked, 1);
}

#[tokio::test]
async fn test_timeline_and_stats_agree_on_malware() {
    let pool = migrated_pool().await;

    insert_log(&pool, false, true, Some("dns_rebinding"), "client", None).await;
    insert_log(&pool, false, true, Some("dga_detection"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;

    let repo = repo(&pool);
    let stats = repo.get_stats(24.0).await.unwrap();
    let timeline = repo.get_timeline(24.0, TimeGranularity::Day).await.unwrap();

    assert_eq!(stats.queries_malware_detected, 2);
    assert_eq!(
        timeline.iter().map(|b| b.malware_detected).sum::<u64>(),
        2,
        "the chart must count the same threat verdicts as the summary"
    );
}

#[tokio::test]
async fn test_top_domains_split_by_verdict() {
    let pool = migrated_pool().await;

    let blocked = |domain| Row {
        domain,
        blocked: true,
        block_source: Some("blocklist"),
        ..Row::default()
    };
    for _ in 0..3 {
        insert(&pool, blocked("ads.example.com")).await;
    }
    for _ in 0..5 {
        insert(&pool, blocked("tracker.example.com")).await;
    }
    for _ in 0..4 {
        insert(
            &pool,
            Row {
                domain: "safe.example.com",
                ..Row::default()
            },
        )
        .await;
    }
    insert(
        &pool,
        Row {
            domain: "internal.example.com",
            query_source: "internal",
            ..Row::default()
        },
    )
    .await;

    let repo = repo(&pool);
    let owned = |pairs: &[(&str, u64)]| -> Vec<(String, u64)> {
        pairs.iter().map(|(d, n)| (d.to_string(), *n)).collect()
    };

    assert_eq!(
        repo.get_top_blocked_domains(15, 24.0).await.unwrap(),
        owned(&[("tracker.example.com", 5), ("ads.example.com", 3)])
    );
    assert_eq!(
        repo.get_top_allowed_domains(15, 24.0).await.unwrap(),
        owned(&[("safe.example.com", 4)])
    );
    assert_eq!(
        repo.get_distinct_recent_domains(2, 24.0).await.unwrap(),
        owned(&[("tracker.example.com", 5), ("safe.example.com", 4)])
    );
}

#[tokio::test]
async fn test_get_top_clients_returns_sorted_with_hostname() {
    let pool = migrated_pool().await;

    insert_client(&pool, "192.168.1.10", "desktop-pc").await;
    let from = |client_ip, query_source| Row {
        client_ip,
        query_source,
        ..Row::default()
    };
    for _ in 0..4 {
        insert(&pool, from("192.168.1.10", "client")).await;
    }
    for _ in 0..2 {
        insert(&pool, from("192.168.1.20", "client")).await;
    }
    insert(&pool, from("192.168.1.20", "internal")).await;

    let result = repo(&pool).get_top_clients(15, 24.0).await.unwrap();

    assert_eq!(
        result,
        vec![
            (
                "192.168.1.10".to_string(),
                Some("desktop-pc".to_string()),
                4
            ),
            ("192.168.1.20".to_string(), None, 2),
        ]
    );
}

async fn insert_query(
    pool: &SqlitePool,
    domain: &str,
    blocked: bool,
    cache_hit: bool,
    block_source: Option<&str>,
    response_status: Option<&str>,
) {
    insert(
        pool,
        Row {
            domain,
            blocked,
            cache_hit,
            block_source,
            response_status,
            ..Row::default()
        },
    )
    .await;
}

async fn seed_mixed_queries(pool: &SqlitePool) {
    // 2 allowed (not blocked, not cache)
    insert_query(pool, "google.com", false, false, None, None).await;
    insert_query(pool, "github.com", false, false, None, None).await;
    // 2 blocked
    insert_query(
        pool,
        "ads.example.com",
        true,
        false,
        Some("blocklist"),
        None,
    )
    .await;
    insert_query(
        pool,
        "tracker.example.com",
        true,
        false,
        Some("managed_domain"),
        None,
    )
    .await;
    // 2 cache hits
    insert_query(pool, "cached.example.com", false, true, None, None).await;
    insert_query(pool, "cached2.example.com", false, true, None, None).await;
    // 1 rate limited
    insert_query(
        pool,
        "rate.example.com",
        false,
        false,
        None,
        Some("RATE_LIMITED"),
    )
    .await;
    // 1 malware (tunneling)
    insert_query(
        pool,
        "tunnel.example.com",
        true,
        false,
        Some("dns_tunneling"),
        None,
    )
    .await;
    // 1 malware (dga)
    insert_query(
        pool,
        "xjk4f9a2h.com",
        true,
        false,
        Some("dga_detection"),
        None,
    )
    .await;
    // 1 local DNS
    insert_query(pool, "local.home", false, false, None, Some("LOCAL_DNS")).await;
}

#[tokio::test]
async fn test_category_filter_all_returns_everything() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &no_filter())
        .await
        .unwrap();
    assert_eq!(result.records_filtered, 10);
    assert_eq!(result.records_total, 10);
    assert_eq!(result.queries.len(), 10);
}

#[tokio::test]
async fn test_category_filter_allowed() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Allowed),
        )
        .await
        .unwrap();
    // allowed = not blocked: google, github, cached, cached2, rate, local = 6
    assert_eq!(result.records_filtered, 6);
    assert_eq!(result.queries.len(), 6);
    assert!(result.queries.iter().all(|q| !q.blocked));
}

#[tokio::test]
async fn test_category_filter_blocked() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Blocked),
        )
        .await
        .unwrap();
    // blocked: ads, tracker, tunnel, dga = 4
    assert_eq!(result.records_filtered, 4);
    assert_eq!(result.queries.len(), 4);
    assert!(result.queries.iter().all(|q| q.blocked));
}

#[tokio::test]
async fn test_category_filter_cache() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Cache),
        )
        .await
        .unwrap();
    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
    assert!(result.queries.iter().all(|q| q.cache_hit));
}

#[tokio::test]
async fn test_category_filter_upstream() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Upstream),
        )
        .await
        .unwrap();
    // upstream = not blocked, not cache, not rate_limited, not local_dns: google, github = 2
    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
    assert!(result.queries.iter().all(|q| !q.blocked && !q.cache_hit));
}

#[tokio::test]
async fn test_category_filter_rate_limited() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::RateLimited),
        )
        .await
        .unwrap();
    assert_eq!(result.records_filtered, 1);
    assert_eq!(result.queries.len(), 1);
}

#[tokio::test]
async fn test_category_filter_malware() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Malware),
        )
        .await
        .unwrap();
    // malware: tunnel + dga = 2
    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
}

#[tokio::test]
async fn test_category_filter_combined_with_domain_search() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let filter = QueryLogFilter {
        domain: Some("example".to_string()),
        category: Some(QueryCategory::Blocked),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();
    // blocked + "example": ads.example.com, tracker.example.com, tunnel.example.com = 3
    assert_eq!(result.records_filtered, 3);
    assert_eq!(result.queries.len(), 3);
    assert!(result.queries.iter().all(|q| q.blocked));
}

#[tokio::test]
async fn test_category_filter_respects_pagination() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let repo = repo(&pool);
    let blocked_filter = category_filter(QueryCategory::Blocked);

    let page1 = repo
        .get_recent_paged(2, PageAt::Offset(0), 24.0, &blocked_filter)
        .await
        .unwrap();
    assert_eq!(page1.records_filtered, 4);
    assert_eq!(page1.queries.len(), 2);
    assert!(page1.queries.iter().all(|q| q.blocked));

    let page2 = repo
        .get_recent_paged(2, PageAt::Offset(2), 24.0, &blocked_filter)
        .await
        .unwrap();
    assert_eq!(page2.records_filtered, 4);
    assert_eq!(page2.queries.len(), 2);
    assert!(page2.queries.iter().all(|q| q.blocked));

    let ids1: Vec<_> = page1.queries.iter().filter_map(|q| q.id).collect();
    let ids2: Vec<_> = page2.queries.iter().filter_map(|q| q.id).collect();
    assert!(
        ids1.iter().all(|id| !ids2.contains(id)),
        "Pages should not overlap"
    );
}

/// Rows of one writer flush share `created_at`; the index orders such ties by
/// `blocked` before `id`, so paging must not rely on the scan order.
#[tokio::test]
async fn test_offset_then_cursor_pages_cover_same_second_rows_once() {
    let pool = migrated_pool().await;
    for (domain, blocked) in [
        ("q1.com", false),
        ("q2.com", true),
        ("q3.com", false),
        ("q4.com", false),
    ] {
        insert(
            &pool,
            Row {
                domain,
                blocked,
                ..Row::default()
            },
        )
        .await;
    }
    sqlx::query("UPDATE query_log SET created_at = (SELECT MAX(created_at) FROM query_log)")
        .execute(&pool)
        .await
        .unwrap();

    let repo = repo(&pool);
    let first = repo
        .get_recent_paged(2, PageAt::Offset(0), 24.0, &no_filter())
        .await
        .unwrap();
    let mut seen: Vec<&str> = first.queries.iter().map(|q| q.domain.as_ref()).collect();
    assert_eq!(seen, ["q4.com", "q3.com"], "newest first");

    let mut cursor = first.next_cursor;
    let mut rest = Vec::new();
    while let Some(c) = cursor {
        let page = repo
            .get_recent_paged(2, PageAt::Cursor(c), 24.0, &no_filter())
            .await
            .unwrap();
        cursor = page.next_cursor;
        rest.extend(page.queries);
    }
    seen.extend(rest.iter().map(|q| q.domain.as_ref()));
    assert_eq!(seen, ["q4.com", "q3.com", "q2.com", "q1.com"]);
}

#[tokio::test]
async fn test_client_ip_filter() {
    let pool = migrated_pool().await;
    for (domain, client_ip) in [
        ("a.com", "10.0.0.1"),
        ("b.com", "10.0.0.1"),
        ("c.com", "10.0.0.2"),
    ] {
        insert(
            &pool,
            Row {
                domain,
                client_ip,
                ..Row::default()
            },
        )
        .await;
    }

    let filter = QueryLogFilter {
        client: Some("10.0.0.1".to_string()),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
    assert!(result
        .queries
        .iter()
        .all(|q| q.client_ip.to_string() == "10.0.0.1"));
}

#[tokio::test]
async fn test_client_filter_partial_ip() {
    let pool = migrated_pool().await;
    for (domain, client_ip) in [
        ("a.com", "10.0.0.1"),
        ("b.com", "10.0.0.2"),
        ("c.com", "10.0.10.5"),
    ] {
        insert(
            &pool,
            Row {
                domain,
                client_ip,
                ..Row::default()
            },
        )
        .await;
    }

    // Substring "10.0.0." matches the two 10.0.0.x clients but not 10.0.10.5.
    let filter = QueryLogFilter {
        client: Some("10.0.0.".to_string()),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
    assert!(result
        .queries
        .iter()
        .all(|q| q.client_ip.to_string().starts_with("10.0.0.")));
}

#[tokio::test]
async fn test_client_filter_hostname() {
    let pool = migrated_pool().await;
    for (domain, client_ip) in [("a.com", "10.0.10.1"), ("b.com", "10.0.10.2")] {
        insert(
            &pool,
            Row {
                domain,
                client_ip,
                ..Row::default()
            },
        )
        .await;
    }
    // 10.0.10.2 has no clients row.
    insert_client(&pool, "10.0.10.1", "Win_viudes.lan.").await;

    // Case-insensitive substring match on the joined hostname.
    let filter = QueryLogFilter {
        client: Some("win_viudes".to_string()),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 1);
    assert_eq!(result.queries.len(), 1);
    assert_eq!(result.queries[0].client_ip.to_string(), "10.0.10.1");
    assert_eq!(
        result.queries[0].client_hostname.as_deref(),
        Some("Win_viudes.lan.")
    );
}

#[tokio::test]
async fn test_search_filters_match_like_wildcards_literally() {
    let pool = migrated_pool().await;
    for (domain, client_ip) in [
        ("a_c.example", "10.0.0.1"),
        ("abc.example", "10.0.0.2"),
        ("100%.example", "10.0.0.3"),
    ] {
        insert(
            &pool,
            Row {
                domain,
                client_ip,
                ..Row::default()
            },
        )
        .await;
    }
    insert_client(&pool, "10.0.0.1", "nas_box").await;
    insert_client(&pool, "10.0.0.2", "nasXbox").await;

    let by_domain = |d: &str| QueryLogFilter {
        domain: Some(d.to_string()),
        ..Default::default()
    };
    assert_eq!(
        domains(&page(&pool, 100, &by_domain("a_c")).await),
        BTreeSet::from(["a_c.example"])
    );
    assert_eq!(
        domains(&page(&pool, 100, &by_domain("0%")).await),
        BTreeSet::from(["100%.example"])
    );

    let by_client = QueryLogFilter {
        client: Some("nas_box".to_string()),
        ..Default::default()
    };
    assert_eq!(
        domains(&page(&pool, 100, &by_client).await),
        BTreeSet::from(["a_c.example"])
    );
}

#[tokio::test]
async fn test_record_type_filter() {
    let pool = migrated_pool().await;
    for (domain, record_type) in [
        ("a.com", "A"),
        ("b.com", "AAAA"),
        ("c.com", "AAAA"),
        ("d.com", "MX"),
    ] {
        insert(
            &pool,
            Row {
                domain,
                record_type,
                ..Row::default()
            },
        )
        .await;
    }

    let filter = QueryLogFilter {
        record_type: Some(RecordType::AAAA),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
    assert!(result
        .queries
        .iter()
        .all(|q| q.record_type == RecordType::AAAA));
}

#[tokio::test]
async fn test_dns64_synthesized_filter() {
    let pool = migrated_pool().await;
    for (domain, record_type, dns64_synthesized) in [
        ("synth.example.com", "AAAA", true),
        ("real.example.com", "AAAA", false),
        ("plain.example.com", "A", false),
    ] {
        insert(
            &pool,
            Row {
                domain,
                record_type,
                dns64_synthesized,
                response_status: Some("NOERROR"),
                ..Row::default()
            },
        )
        .await;
    }

    let repo = repo(&pool);
    let with_dns64 = |dns64_synthesized| QueryLogFilter {
        dns64_synthesized,
        ..Default::default()
    };

    // dns64=Some(true): only the synthesized row, and the flag round-trips from SQLite.
    let only_synth = repo
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &with_dns64(Some(true)))
        .await
        .unwrap();
    assert_eq!(only_synth.records_filtered, 1);
    assert_eq!(only_synth.queries.len(), 1);
    assert_eq!(&*only_synth.queries[0].domain, "synth.example.com");
    assert!(only_synth.queries[0].dns64_synthesized);

    let non_synth = repo
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &with_dns64(Some(false)))
        .await
        .unwrap();
    assert_eq!(non_synth.records_filtered, 2);
    assert!(non_synth.queries.iter().all(|q| !q.dns64_synthesized));

    let all = repo
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &with_dns64(None))
        .await
        .unwrap();
    assert_eq!(all.records_filtered, 3);
}

#[tokio::test]
async fn test_upstream_filter() {
    let pool = migrated_pool().await;
    for (domain, upstream) in [
        ("a.com", "8.8.8.8"),
        ("b.com", "8.8.8.8"),
        ("c.com", "1.1.1.1"),
    ] {
        insert(
            &pool,
            Row {
                domain,
                upstream_server: Some(upstream),
                ..Row::default()
            },
        )
        .await;
    }

    let filter = QueryLogFilter {
        upstream: Some("8.8.8.8".to_string()),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 2);
    assert_eq!(result.queries.len(), 2);
}

#[tokio::test]
async fn test_records_total_vs_filtered() {
    let pool = migrated_pool().await;
    seed_mixed_queries(&pool).await;

    let result = repo(&pool)
        .get_recent_paged(
            100,
            PageAt::Offset(0),
            24.0,
            &category_filter(QueryCategory::Blocked),
        )
        .await
        .unwrap();

    assert_eq!(result.records_total, 10);
    assert_eq!(result.records_filtered, 4);
}

#[tokio::test]
async fn test_combined_client_and_category() {
    let pool = migrated_pool().await;
    for (domain, client_ip, blocked) in [
        ("a.com", "10.0.0.1", true),
        ("b.com", "10.0.0.1", false),
        ("c.com", "10.0.0.2", true),
    ] {
        insert(
            &pool,
            Row {
                domain,
                client_ip,
                blocked,
                block_source: blocked.then_some("blocklist"),
                ..Row::default()
            },
        )
        .await;
    }

    let filter = QueryLogFilter {
        category: Some(QueryCategory::Blocked),
        client: Some("10.0.0.1".to_string()),
        ..Default::default()
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 1);
    assert_eq!(result.queries.len(), 1);
    assert!(result.queries[0].blocked);
    assert_eq!(result.queries[0].client_ip.to_string(), "10.0.0.1");
}

#[tokio::test]
async fn test_combined_all_filters() {
    let pool = migrated_pool().await;

    let matching = Row {
        domain: "match.example.com",
        client_ip: "10.0.0.1",
        record_type: "AAAA",
        blocked: true,
        block_source: Some("blocklist"),
        upstream_server: Some("8.8.8.8"),
        ..Row::default()
    };
    let inserts = [
        matching,
        Row {
            client_ip: "10.0.0.2",
            ..matching
        },
        Row {
            record_type: "A",
            ..matching
        },
        Row {
            upstream_server: Some("1.1.1.1"),
            ..matching
        },
        Row {
            blocked: false,
            block_source: None,
            ..matching
        },
        Row {
            domain: "other.com",
            ..matching
        },
    ];
    for row in inserts {
        insert(&pool, row).await;
    }

    let filter = QueryLogFilter {
        domain: Some("example".to_string()),
        category: Some(QueryCategory::Blocked),
        client: Some("10.0.0.1".to_string()),
        record_type: Some(RecordType::AAAA),
        upstream: Some("8.8.8.8".to_string()),
        dnssec_status: None,
        dns64_synthesized: None,
        protocol: None,
    };
    let result = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(result.records_filtered, 1);
    assert_eq!(result.queries.len(), 1);
    assert_eq!(result.records_total, inserts.len() as u64);
}

#[tokio::test]
async fn test_cursor_pagination_with_client_filter() {
    let pool = migrated_pool().await;

    for i in 0..5 {
        let domain = format!("q{i}.com");
        insert(
            &pool,
            Row {
                domain: &domain,
                client_ip: "10.0.0.1",
                ..Row::default()
            },
        )
        .await;
    }
    for i in 0..2 {
        let domain = format!("other{i}.com");
        insert(
            &pool,
            Row {
                domain: &domain,
                client_ip: "10.0.0.2",
                ..Row::default()
            },
        )
        .await;
    }

    let repo = repo(&pool);
    let filter = QueryLogFilter {
        client: Some("10.0.0.1".to_string()),
        ..Default::default()
    };

    let page1 = repo
        .get_recent_paged(3, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();
    assert_eq!(page1.queries.len(), 3);
    assert_eq!(page1.records_filtered, 5);
    assert!(page1.next_cursor.is_some());

    let page2 = repo
        .get_recent_paged(3, PageAt::Cursor(page1.next_cursor.unwrap()), 24.0, &filter)
        .await
        .unwrap();
    assert_eq!(page2.queries.len(), 2);
    assert!(page2.next_cursor.is_none());

    assert!(page1
        .queries
        .iter()
        .chain(page2.queries.iter())
        .all(|q| q.client_ip.to_string() == "10.0.0.1"));

    let ids1: Vec<_> = page1.queries.iter().filter_map(|q| q.id).collect();
    let ids2: Vec<_> = page2.queries.iter().filter_map(|q| q.id).collect();
    assert!(ids1.iter().all(|id| !ids2.contains(id)));
}

#[tokio::test]
async fn test_answers_round_trip_from_sqlite() {
    let pool = migrated_pool().await;
    for (domain, answers) in [
        (
            "multi.example.com",
            Some("93.184.216.34,2606:2800:220:1:248:1893:25c8:1946"),
        ),
        ("none.example.com", None),
        ("garbage.example.com", Some("not-an-ip")),
    ] {
        insert(
            &pool,
            Row {
                domain,
                answers,
                client_ip: "10.0.0.1",
                response_status: Some("NOERROR"),
                ..Row::default()
            },
        )
        .await;
    }

    let queries = page(&pool, 100, &no_filter()).await;
    let row = |domain: &str| {
        queries
            .iter()
            .find(|q| &*q.domain == domain)
            .unwrap_or_else(|| panic!("{domain} missing from the page"))
    };

    let answers = row("multi.example.com")
        .answers
        .as_ref()
        .expect("stored addresses must round-trip");
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].to_string(), "93.184.216.34");
    assert_eq!(answers[1].to_string(), "2606:2800:220:1:248:1893:25c8:1946");

    assert!(row("none.example.com").answers.is_none());
    // Unparseable text is dropped rather than surfacing a bogus address.
    assert!(row("garbage.example.com").answers.is_none());
}

#[tokio::test]
async fn test_logged_answers_are_capped() {
    let pool = migrated_pool().await;
    let repo = repo(&pool);

    let addresses: Vec<IpAddr> = (1..=6u8).map(|n| IpAddr::from([192, 0, 2, n])).collect();
    repo.log_query(&QueryLog {
        answers: Some(Arc::new(addresses)),
        ..client_query("cdn.example.com", Some(ClientProtocol::Udp))
    })
    .await
    .unwrap();

    assert!(
        wait_for_flush(&pool).await,
        "the batched write never reached the database"
    );
    let stored: Option<String> = sqlx::query_scalar("SELECT answers FROM query_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some("192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4"),
        "only the first four addresses are persisted"
    );
}

#[tokio::test]
async fn test_protocol_reads_back_and_is_none_for_pre_migration_rows() {
    let pool = migrated_pool().await;
    for (domain, protocol) in [
        ("udp.example.com", Some("udp")),
        ("dot.example.com", Some("dot")),
        // A row written before the column existed reads back as NULL.
        ("legacy.example.com", None),
    ] {
        insert(
            &pool,
            Row {
                domain,
                protocol,
                ..Row::default()
            },
        )
        .await;
    }

    let queries = page(&pool, 100, &no_filter()).await;
    assert_eq!(queries.len(), 3);

    let protocol_of = |domain: &str| {
        queries
            .iter()
            .find(|q| q.domain.as_ref() == domain)
            .unwrap_or_else(|| panic!("{domain} must be in the page"))
            .protocol
    };
    assert_eq!(protocol_of("udp.example.com"), Some(ClientProtocol::Udp));
    assert_eq!(protocol_of("dot.example.com"), Some(ClientProtocol::Dot));
    assert_eq!(protocol_of("legacy.example.com"), None);
}

#[tokio::test]
async fn test_protocol_filter_keeps_only_matching_rows() {
    let pool = migrated_pool().await;
    for (domain, protocol) in [
        ("udp.example.com", Some("udp")),
        ("dot.example.com", Some("dot")),
        ("legacy.example.com", None),
    ] {
        insert(
            &pool,
            Row {
                domain,
                protocol,
                ..Row::default()
            },
        )
        .await;
    }

    let filter = QueryLogFilter {
        protocol: Some(ClientProtocol::Dot),
        ..Default::default()
    };
    let page = repo(&pool)
        .get_recent_paged(100, PageAt::Offset(0), 24.0, &filter)
        .await
        .unwrap();

    assert_eq!(page.queries.len(), 1);
    assert_eq!(page.queries[0].domain.as_ref(), "dot.example.com");
    assert_eq!(page.records_filtered, 1);
    // The unfiltered total is unaffected by the protocol filter.
    assert_eq!(page.records_total, 3);
}

#[tokio::test]
async fn test_logged_protocol_is_persisted() {
    let pool = migrated_pool().await;
    repo(&pool)
        .log_query(&client_query("quic.example.com", Some(ClientProtocol::Doq)))
        .await
        .unwrap();

    assert!(
        wait_for_flush(&pool).await,
        "the batched write never reached the database"
    );
    let stored: Option<String> = sqlx::query_scalar("SELECT protocol FROM query_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.as_deref(), Some("doq"));
}

#[tokio::test]
async fn test_unparseable_created_at_reads_back_without_timestamp() {
    let pool = migrated_pool().await;
    insert(
        &pool,
        Row {
            domain: "corrupt.example.com",
            created_at: Some("not-a-date"),
            ..Row::default()
        },
    )
    .await;

    let recent = repo(&pool).get_recent(10, 24.0).await.unwrap();

    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].domain.as_ref(), "corrupt.example.com");
    assert_eq!(recent[0].timestamp, None);
}

#[tokio::test]
async fn test_delete_older_than_drops_old_rows_and_their_rollups() {
    let pool = migrated_pool().await;
    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(
        &pool,
        false,
        false,
        None,
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;
    let repo = repo(&pool);
    let all_time = 24.0 * 365.0 * 100.0;
    assert_eq!(repo.get_stats(all_time).await.unwrap().queries_total, 2);

    assert_eq!(repo.delete_older_than(30).await.unwrap(), 1);

    assert_eq!(page(&pool, 100, &no_filter()).await.len(), 1);
    assert_eq!(repo.get_stats(all_time).await.unwrap().queries_total, 1);
}

#[tokio::test]
async fn test_delete_older_than_beyond_calendar_range_keeps_everything() {
    let pool = migrated_pool().await;
    insert_log(
        &pool,
        false,
        false,
        None,
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;

    assert_eq!(repo(&pool).delete_older_than(u32::MAX).await.unwrap(), 0);

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

/// `created_at` of a row `minutes` before now, in the column's format.
fn minutes_ago(minutes: i64) -> String {
    (chrono::Utc::now() - chrono::TimeDelta::minutes(minutes))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// A backwards clock step gives a newer row (higher id) an older timestamp.
/// Pages follow the first page's `(created_at, id)` order, so paging from a
/// cursor visits every row exactly once, in the same order offsets would.
#[tokio::test]
async fn cursor_pages_do_not_skip_rows_written_after_a_clock_step() {
    let pool = migrated_pool().await;
    let (now, earlier) = (minutes_ago(1), minutes_ago(5));
    for (domain, created_at) in [("a.com", &now), ("b.com", &now), ("stepped.com", &earlier)] {
        insert(
            &pool,
            Row {
                domain,
                created_at: Some(created_at),
                ..Row::default()
            },
        )
        .await;
    }
    let repo = repo(&pool);

    let by_offset = repo
        .get_recent_paged(10, PageAt::Offset(0), 24.0, &no_filter())
        .await
        .unwrap();
    let expected: Vec<_> = by_offset.queries.iter().map(|q| q.domain.clone()).collect();
    assert_eq!(expected.len(), 3);

    let mut page = repo
        .get_recent_paged(1, PageAt::Offset(0), 24.0, &no_filter())
        .await
        .unwrap();
    let mut seen: Vec<_> = page.queries.iter().map(|q| q.domain.clone()).collect();
    while let Some(cursor) = page.next_cursor {
        page = repo
            .get_recent_paged(1, PageAt::Cursor(cursor), 24.0, &no_filter())
            .await
            .unwrap();
        seen.extend(page.queries.iter().map(|q| q.domain.clone()));
    }
    assert_eq!(seen, expected);
}

/// Retention can delete the row a client's cursor points at; the next page
/// must continue below that id instead of coming back empty.
#[tokio::test]
async fn a_cursor_whose_row_was_deleted_continues_below_its_id() {
    let pool = migrated_pool().await;
    for (domain, minutes) in [("old.com", 30), ("cursor.com", 20), ("new.com", 10)] {
        insert(
            &pool,
            Row {
                domain,
                created_at: Some(&minutes_ago(minutes)),
                ..Row::default()
            },
        )
        .await;
    }
    let repo = repo(&pool);
    let first = repo
        .get_recent_paged(2, PageAt::Offset(0), 24.0, &no_filter())
        .await
        .unwrap();
    let cursor = first.next_cursor.unwrap();
    assert_eq!(
        domains(&first.queries),
        BTreeSet::from(["new.com", "cursor.com"])
    );

    sqlx::query("DELETE FROM query_log WHERE id = ?")
        .bind(cursor)
        .execute(&pool)
        .await
        .unwrap();
    let next = repo
        .get_recent_paged(2, PageAt::Cursor(cursor), 24.0, &no_filter())
        .await
        .unwrap();

    assert_eq!(domains(&next.queries), BTreeSet::from(["old.com"]));
    assert_eq!(next.next_cursor, None);
}

/// A window shorter than an hour is not rounded down to nothing.
#[tokio::test]
async fn timeline_honours_a_sub_hour_period() {
    let pool = migrated_pool().await;
    insert_log(&pool, false, false, None, "client", Some(&minutes_ago(10))).await;
    insert_log(&pool, false, false, None, "client", Some(&minutes_ago(50))).await;

    let buckets = repo(&pool)
        .get_timeline(0.5, TimeGranularity::Minute)
        .await
        .unwrap();
    assert_eq!(buckets.iter().map(|b| b.total).sum::<u64>(), 1);
}

#[tokio::test]
async fn timeline_with_an_unbounded_period_covers_all_history() {
    let pool = migrated_pool().await;
    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(
        &pool,
        false,
        false,
        None,
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;

    let buckets = repo(&pool)
        .get_timeline(f32::MAX, TimeGranularity::Day)
        .await
        .unwrap();
    assert_eq!(buckets.iter().map(|b| b.total).sum::<u64>(), 2);
}
