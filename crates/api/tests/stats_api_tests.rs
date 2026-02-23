use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_application::{
    ports::{BlockFilterEnginePort, FilterDecision},
    use_cases::{
        GetBlockFilterStatsUseCase, GetBlocklistUseCase, GetClientsUseCase, GetQueryStatsUseCase,
        GetRecentQueriesUseCase,
    },
};
use ferrous_dns_domain::{config::DatabaseConfig, Config};
use ferrous_dns_infrastructure::{
    dns::{cache::DnsCache, HickoryDnsResolver},
    repositories::{
        client_repository::SqliteClientRepository, query_log_repository::SqliteQueryLogRepository,
        regex_filter_repository::SqliteRegexFilterRepository,
    },
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

struct NullBlockFilterEngine;

#[async_trait::async_trait]
impl BlockFilterEnginePort for NullBlockFilterEngine {
    fn resolve_group(&self, _ip: std::net::IpAddr) -> i64 {
        1
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    async fn reload(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
}

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO groups (id, name, enabled, comment, is_default)
        VALUES (1, 'Protected', 1, 'Default group', 1)
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
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count INTEGER NOT NULL DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE regex_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id INTEGER NOT NULL DEFAULT 1,
            comment TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
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

async fn create_test_app(pool: sqlx::SqlitePool) -> Router {
    let client_repo = Arc::new(SqliteClientRepository::new(
        pool.clone(),
        &DatabaseConfig::default(),
    ));
    let group_repo = Arc::new(
        ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(
            pool.clone(),
        ),
    );
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let query_log_repo = Arc::new(SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    ));

    let config = Arc::new(RwLock::new(Config::default()));
    let cache = Arc::new(DnsCache::new(
        ferrous_dns_infrastructure::dns::DnsCacheConfig {
            max_entries: 0,
            eviction_strategy: ferrous_dns_infrastructure::dns::EvictionStrategy::LRU,
            min_threshold: 0.0,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: 0,
            max_ttl: 86_400,
        },
    ));

    use ferrous_dns_domain::config::upstream::{UpstreamPool, UpstreamStrategy};
    use ferrous_dns_infrastructure::dns::{PoolManager, QueryEventEmitter};

    let event_emitter = QueryEventEmitter::new_disabled();
    let test_pool = UpstreamPool {
        name: "test".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["8.8.8.8:53".to_string()],
        weight: None,
    };
    let pool_manager = Arc::new(
        PoolManager::new(vec![test_pool], None, event_emitter)
            .expect("Failed to create PoolManager"),
    );

    let state = AppState {
        get_stats: Arc::new(GetQueryStatsUseCase::new(query_log_repo.clone())),
        get_queries: Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone())),
        get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
        ))),
        get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
        get_groups: Arc::new(ferrous_dns_application::use_cases::GetGroupsUseCase::new(group_repo.clone())),
        create_group: Arc::new(ferrous_dns_application::use_cases::CreateGroupUseCase::new(group_repo.clone())),
        update_group: Arc::new(ferrous_dns_application::use_cases::UpdateGroupUseCase::new(group_repo.clone())),
        delete_group: Arc::new(ferrous_dns_application::use_cases::DeleteGroupUseCase::new(group_repo.clone())),
        assign_client_group: Arc::new(ferrous_dns_application::use_cases::AssignClientGroupUseCase::new(
            client_repo.clone(),
            group_repo.clone(),
        )),
        get_client_subnets: Arc::new(ferrous_dns_application::use_cases::GetClientSubnetsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
        ))),
        create_client_subnet: Arc::new(ferrous_dns_application::use_cases::CreateClientSubnetUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        delete_client_subnet: Arc::new(ferrous_dns_application::use_cases::DeleteClientSubnetUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
        ))),
        create_manual_client: Arc::new(ferrous_dns_application::use_cases::CreateManualClientUseCase::new(
            client_repo.clone(),
            group_repo.clone(),
        )),
        update_client: Arc::new(ferrous_dns_application::use_cases::UpdateClientUseCase::new(client_repo.clone())),
        delete_client: Arc::new(ferrous_dns_application::use_cases::DeleteClientUseCase::new(client_repo.clone())),
        get_blocklist_sources: Arc::new(ferrous_dns_application::use_cases::GetBlocklistSourcesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
        ))),
        create_blocklist_source: Arc::new(ferrous_dns_application::use_cases::CreateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        update_blocklist_source: Arc::new(ferrous_dns_application::use_cases::UpdateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        delete_blocklist_source: Arc::new(ferrous_dns_application::use_cases::DeleteBlocklistSourceUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
        ))),
        get_whitelist: Arc::new(ferrous_dns_application::use_cases::GetWhitelistUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::whitelist_repository::SqliteWhitelistRepository::new(pool.clone()),
        ))),
        get_whitelist_sources: Arc::new(ferrous_dns_application::use_cases::GetWhitelistSourcesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone()),
        ))),
        create_whitelist_source: Arc::new(ferrous_dns_application::use_cases::CreateWhitelistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        update_whitelist_source: Arc::new(ferrous_dns_application::use_cases::UpdateWhitelistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        delete_whitelist_source: Arc::new(ferrous_dns_application::use_cases::DeleteWhitelistSourceUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone()),
        ))),
        get_managed_domains: Arc::new(ferrous_dns_application::use_cases::GetManagedDomainsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone()),
        ))),
        create_managed_domain: Arc::new(ferrous_dns_application::use_cases::CreateManagedDomainUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            group_repo.clone(),
            Arc::new(NullBlockFilterEngine),
        )),
        update_managed_domain: Arc::new(ferrous_dns_application::use_cases::UpdateManagedDomainUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            group_repo.clone(),
            Arc::new(NullBlockFilterEngine),
        )),
        delete_managed_domain: Arc::new(ferrous_dns_application::use_cases::DeleteManagedDomainUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            Arc::new(NullBlockFilterEngine),
        )),
        get_regex_filters: Arc::new(ferrous_dns_application::use_cases::GetRegexFiltersUseCase::new(
            regex_filter_repo.clone(),
        )),
        create_regex_filter: Arc::new(ferrous_dns_application::use_cases::CreateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            Arc::new(NullBlockFilterEngine),
        )),
        update_regex_filter: Arc::new(ferrous_dns_application::use_cases::UpdateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            Arc::new(NullBlockFilterEngine),
        )),
        delete_regex_filter: Arc::new(ferrous_dns_application::use_cases::DeleteRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            Arc::new(NullBlockFilterEngine),
        )),
        subnet_matcher: Arc::new(ferrous_dns_application::services::SubnetMatcherService::new(Arc::new(
            ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
        ))),
        get_timeline: Arc::new(ferrous_dns_application::use_cases::GetTimelineUseCase::new(query_log_repo.clone())),
        get_query_rate: Arc::new(ferrous_dns_application::use_cases::GetQueryRateUseCase::new(query_log_repo.clone())),
        get_cache_stats: Arc::new(ferrous_dns_application::use_cases::GetCacheStatsUseCase::new(query_log_repo.clone())),
        get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
        config,
        cache,
        dns_resolver: Arc::new(
            HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap(),
        ),
        api_key: None,
    };

    create_api_routes(state)
}

async fn insert_query_log(
    pool: &sqlx::SqlitePool,
    cache_hit: bool,
    blocked: bool,
    block_source: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source)
         VALUES ('example.com', 'A', '192.168.1.1', ?, 100, ?, 'client', ?)",
    )
    .bind(if blocked { 1i64 } else { 0i64 })
    .bind(if cache_hit { 1i64 } else { 0i64 })
    .bind(block_source)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn test_get_stats_empty() {
    let pool = create_test_db().await;
    let app = create_test_app(pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["queries_total"], 0);
    assert_eq!(json["queries_blocked"], 0);
}

#[tokio::test]
async fn test_get_stats_has_source_stats_field() {
    let pool = create_test_db().await;
    let app = create_test_app(pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let ss = &json["source_stats"];
    assert!(ss.is_object(), "source_stats must be an object");
    assert!(ss["cache_hits"].is_number());
    assert!(ss["upstream"].is_number());
    assert!(ss["blocked_by_blocklist"].is_number());
    assert!(ss["blocked_by_managed_domain"].is_number());
    assert!(ss["blocked_by_regex_filter"].is_number());
}

#[tokio::test]
async fn test_get_stats_with_data() {
    let pool = create_test_db().await;

    // 2 cache hits + 3 upstream
    insert_query_log(&pool, true, false, None).await;
    insert_query_log(&pool, true, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    // 1 blocklist block
    insert_query_log(&pool, false, true, Some("blocklist")).await;

    let app = create_test_app(pool).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["queries_total"], 6);
    assert_eq!(json["queries_blocked"], 1);

    let ss = &json["source_stats"];
    assert_eq!(ss["cache_hits"], 2);
    assert_eq!(ss["upstream"], 3);
    assert_eq!(ss["blocked_by_blocklist"], 1);
    assert_eq!(ss["blocked_by_managed_domain"], 0);
    assert_eq!(ss["blocked_by_regex_filter"], 0);
}

#[tokio::test]
async fn test_get_stats_period_parameter() {
    let pool = create_test_db().await;

    // Insert 1 recent query
    insert_query_log(&pool, false, false, None).await;
    // Insert 1 old query (far in the past)
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, created_at)
         VALUES ('old.example.com', 'A', '10.0.0.1', 0, 50, 0, 'client', '2000-01-01 00:00:00')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let app = create_test_app(pool).await;

    // 1h period: only the recent query
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats?period=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["queries_total"], 1);
}
