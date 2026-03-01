use ferrous_dns_application::ports::{QueryLogRepository, TimeGranularity};
use ferrous_dns_domain::config::DatabaseConfig;
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
            upstream_pool TEXT,
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

    sqlx::query(
        r#"
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            mac_address TEXT,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count INTEGER NOT NULL DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    let (up_server, up_pool) = if !cache_hit && !blocked {
        ("'dns.google'", "'pool1'")
    } else {
        ("NULL", "NULL")
    };
    let sql = format!(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source, upstream_server, upstream_pool, created_at)
         VALUES ('example.com', 'A', '192.168.1.1', {}, 100, {}, '{}', {}, {}, {}, {})",
        if blocked { 1 } else { 0 },
        if cache_hit { 1 } else { 0 },
        query_source,
        block_source.map_or("NULL".to_string(), |s| format!("'{}'", s)),
        up_server,
        up_pool,
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
    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let stats = repo.get_stats(24.0).await.unwrap();

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
async fn test_get_stats_cache_hits_count() {
    let pool = create_test_db().await;

    for _ in 0..3 {
        insert_log(&pool, true, false, None, "client", None).await;
    }
    for _ in 0..2 {
        insert_log(&pool, false, false, None, "client", None).await;
    }

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 5);
    assert_eq!(stats.source_stats.get("cache"), Some(&3));
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&2));
    assert_eq!(stats.queries_blocked, 0);
}

#[tokio::test]
async fn test_get_stats_blocklist_breakdown() {
    let pool = create_test_db().await;

    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, false, true, Some("managed_domain"), "client", None).await;
    for _ in 0..3 {
        insert_log(&pool, false, true, Some("regex_filter"), "client", None).await;
    }

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 6);
    assert_eq!(stats.source_stats.get("blocklist"), Some(&2));
    assert_eq!(stats.source_stats.get("managed_domain"), Some(&1));
    assert_eq!(stats.source_stats.get("regex_filter"), Some(&3));
    assert_eq!(stats.source_stats.get("cname_cloaking"), None);
}

#[tokio::test]
async fn test_get_stats_cname_cloaking_breakdown() {
    let pool = create_test_db().await;

    insert_log(&pool, false, true, Some("cname_cloaking"), "client", None).await;
    insert_log(&pool, false, true, Some("cname_cloaking"), "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_blocked, 3);
    assert_eq!(stats.source_stats.get("cname_cloaking"), Some(&2));
    assert_eq!(stats.source_stats.get("blocklist"), Some(&1));
}

#[tokio::test]
async fn test_get_stats_excludes_internal_query_source() {
    let pool = create_test_db().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(&pool, false, false, None, "internal", None).await;
    insert_log(&pool, true, false, None, "dnssec_validation", None).await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let stats = repo.get_stats(24.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&1));
    assert_eq!(stats.source_stats.get("cache"), Some(&0));
}

#[tokio::test]
async fn test_get_stats_period_filter() {
    let pool = create_test_db().await;

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

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let stats = repo.get_stats(1.0).await.unwrap();

    assert_eq!(stats.queries_total, 1);
    assert_eq!(stats.source_stats.get("pool1:dns.google"), Some(&1));
}

#[tokio::test]
async fn test_get_timeline_empty() {
    let pool = create_test_db().await;
    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let buckets = repo.get_timeline(24, TimeGranularity::Hour).await.unwrap();

    assert!(buckets.is_empty());
}

#[tokio::test]
async fn test_get_timeline_returns_buckets() {
    let pool = create_test_db().await;

    insert_log(&pool, false, false, None, "client", None).await;
    insert_log(&pool, false, true, Some("blocklist"), "client", None).await;
    insert_log(&pool, true, false, None, "internal", None).await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );
    let buckets = repo.get_timeline(24, TimeGranularity::Hour).await.unwrap();

    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].total, 2);
    assert_eq!(buckets[0].blocked, 1);
    assert_eq!(buckets[0].unblocked, 1);
}

#[tokio::test]
async fn test_get_timeline_cache_hit_returns_stale_data() {
    let pool = create_test_db().await;

    insert_log(&pool, false, false, None, "client", None).await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let first_result = repo.get_timeline(24, TimeGranularity::Hour).await.unwrap();
    assert_eq!(first_result.len(), 1);
    assert_eq!(first_result[0].total, 1);

    insert_log(&pool, false, false, None, "client", None).await;

    let cached_result = repo.get_timeline(24, TimeGranularity::Hour).await.unwrap();

    assert_eq!(cached_result.len(), first_result.len());
    assert_eq!(cached_result[0].total, first_result[0].total);
}

async fn insert_log_with_domain(
    pool: &sqlx::SqlitePool,
    domain: &str,
    client_ip: &str,
    blocked: bool,
    block_source: Option<&str>,
    query_source: &str,
) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source)
         VALUES (?, 'A', ?, ?, 100, 0, ?, ?)",
    )
    .bind(domain)
    .bind(client_ip)
    .bind(if blocked { 1i64 } else { 0i64 })
    .bind(query_source)
    .bind(block_source)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn test_get_top_blocked_domains_empty() {
    let pool = create_test_db().await;
    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let result = repo.get_top_blocked_domains(15, 24.0).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_get_top_blocked_domains_returns_sorted() {
    let pool = create_test_db().await;

    for _ in 0..3 {
        insert_log_with_domain(
            &pool,
            "ads.example.com",
            "192.168.1.1",
            true,
            Some("blocklist"),
            "client",
        )
        .await;
    }
    for _ in 0..5 {
        insert_log_with_domain(
            &pool,
            "tracker.example.com",
            "192.168.1.1",
            true,
            Some("blocklist"),
            "client",
        )
        .await;
    }
    insert_log_with_domain(
        &pool,
        "safe.example.com",
        "192.168.1.1",
        false,
        None,
        "client",
    )
    .await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let result = repo.get_top_blocked_domains(15, 24.0).await.unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "tracker.example.com");
    assert_eq!(result[0].1, 5);
    assert_eq!(result[1].0, "ads.example.com");
    assert_eq!(result[1].1, 3);
}

#[tokio::test]
async fn test_get_top_clients_empty() {
    let pool = create_test_db().await;
    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let result = repo.get_top_clients(15, 24.0).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_get_top_clients_returns_sorted_with_hostname() {
    let pool = create_test_db().await;

    sqlx::query("INSERT INTO clients (ip_address, hostname) VALUES ('192.168.1.10', 'desktop-pc')")
        .execute(&pool)
        .await
        .unwrap();

    for _ in 0..4 {
        insert_log_with_domain(&pool, "example.com", "192.168.1.10", false, None, "client").await;
    }
    for _ in 0..2 {
        insert_log_with_domain(&pool, "example.com", "192.168.1.20", false, None, "client").await;
    }
    insert_log_with_domain(
        &pool,
        "example.com",
        "192.168.1.20",
        false,
        None,
        "internal",
    )
    .await;

    let repo = SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    );

    let result = repo.get_top_clients(15, 24.0).await.unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "192.168.1.10");
    assert_eq!(result[0].1, Some("desktop-pc".to_string()));
    assert_eq!(result[0].2, 4);
    assert_eq!(result[1].0, "192.168.1.20");
    assert_eq!(result[1].1, None);
    assert_eq!(result[1].2, 2);
}
