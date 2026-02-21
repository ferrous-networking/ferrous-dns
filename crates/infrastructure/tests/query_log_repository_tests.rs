use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use sqlx::sqlite::SqlitePoolOptions;

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'A',
            client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
            blocked INTEGER NOT NULL DEFAULT 0,
            response_time_ms INTEGER,
            cache_hit INTEGER NOT NULL DEFAULT 0,
            cache_refresh INTEGER NOT NULL DEFAULT 0,
            dnssec_status TEXT,
            upstream_server TEXT,
            response_status TEXT,
            query_source TEXT NOT NULL DEFAULT 'client',
            group_id INTEGER,
            block_source TEXT,
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

async fn insert_log(
    pool: &sqlx::SqlitePool,
    cache_hit: bool,
    blocked: bool,
    block_source: Option<&str>,
    query_source: &str,
    created_at: Option<&str>,
) {
    let ts = created_at.unwrap_or("datetime('now')");
    let sql = format!(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source, created_at)
         VALUES ('example.com', 'A', '192.168.1.1', {}, 100, {}, '{}', {}, {})",
        if blocked { 1 } else { 0 },
        if cache_hit { 1 } else { 0 },
        query_source,
        block_source.map_or("NULL".to_string(), |s| format!("'{}'", s)),
        if created_at.is_some() {
            format!("'{}'", ts)
        } else {
            "datetime('now')".to_string()
        },
    );
    sqlx::query(&sql).execute(pool).await.unwrap();
}

#[tokio::test]
async fn test_get_stats_empty() {
    let pool = create_test_db().await;
    let repo = SqliteQueryLogRepository::new(pool);

    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 0);
    assert_eq!(stats.queries_blocked, 0);
    assert_eq!(stats.queries_cache_hits, 0);
    assert_eq!(stats.queries_upstream, 0);
    assert_eq!(stats.queries_blocked_by_blocklist, 0);
    assert_eq!(stats.queries_blocked_by_managed_domain, 0);
    assert_eq!(stats.queries_blocked_by_regex_filter, 0);
}

#[tokio::test]
async fn test_get_stats_cache_hits_count() {
    let pool = create_test_db().await;

    // 3 cache hits
    for _ in 0..3 {
        insert_log(&pool, true, false, None, "client", None).await;
    }
    // 2 upstream queries
    for _ in 0..2 {
        insert_log(&pool, false, false, None, "client", None).await;
    }

    let repo = SqliteQueryLogRepository::new(pool);
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 5);
    assert_eq!(stats.queries_cache_hits, 3);
    assert_eq!(stats.queries_upstream, 2);
    assert_eq!(stats.queries_blocked, 0);
}

#[tokio::test]
async fn test_get_stats_blocklist_breakdown() {
    let pool = create_test_db().await;

    // 2 blocklist blocks
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    // 1 managed domain block
    insert_log(&pool, false, true, Some("managed_domain"), "client", None).await;
    // 3 regex filter blocks
    for _ in 0..3 {
        insert_log(&pool, false, true, Some("regex_filter"), "client", None).await;
    }

    let repo = SqliteQueryLogRepository::new(pool);
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 6);
    assert_eq!(stats.queries_blocked_by_blocklist, 2);
    assert_eq!(stats.queries_blocked_by_managed_domain, 1);
    assert_eq!(stats.queries_blocked_by_regex_filter, 3);
}

#[tokio::test]
async fn test_get_stats_excludes_internal_query_source() {
    let pool = create_test_db().await;

    // 1 client query (should be counted)
    insert_log(&pool, false, false, None, "client", None).await;
    // 2 internal queries (should be excluded)
    insert_log(&pool, false, false, None, "internal", None).await;
    insert_log(&pool, true, false, None, "dnssec_validation", None).await;

    let repo = SqliteQueryLogRepository::new(pool);
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.queries_upstream, 1);
    assert_eq!(stats.queries_cache_hits, 0);
}

#[tokio::test]
async fn test_get_stats_period_filter() {
    let pool = create_test_db().await;

    // 1 recent query (inside 1h window)
    insert_log(&pool, false, false, None, "client", None).await;
    // 1 old query (outside 1h window — 2 hours ago)
    insert_log(
        &pool,
        false,
        false,
        None,
        "client",
        Some("2000-01-01 00:00:00"),
    )
    .await;

    let repo = SqliteQueryLogRepository::new(pool);
    // period = 1 hour: old query should be excluded
    let stats = repo.get_stats(1.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.queries_upstream, 1);
}
