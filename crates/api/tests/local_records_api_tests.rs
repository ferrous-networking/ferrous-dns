use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_application::{
    ports::{BlockFilterEnginePort, FilterDecision},
    services::SubnetMatcherService,
    use_cases::{GetBlockFilterStatsUseCase, *},
};
use ferrous_dns_domain::{config::DatabaseConfig, Config, LocalDnsRecord};
use ferrous_dns_infrastructure::{
    dns::{cache::DnsCache, HickoryDnsResolver},
    repositories::{
        client_repository::SqliteClientRepository,
        client_subnet_repository::SqliteClientSubnetRepository,
        group_repository::SqliteGroupRepository,
        managed_domain_repository::SqliteManagedDomainRepository,
        regex_filter_repository::SqliteRegexFilterRepository,
    },
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
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
        "INSERT INTO groups (id, name, is_default) VALUES (1, 'Protected', 1), (2, 'Office', 0)",
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
        CREATE TABLE client_subnets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet_cidr TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE managed_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
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

    pool
}

async fn create_test_app() -> (Router, Arc<RwLock<Config>>) {
    let pool = create_test_db().await;

    let client_repo = Arc::new(SqliteClientRepository::new(
        pool.clone(),
        &DatabaseConfig::default(),
    ));
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let subnet_repo = Arc::new(SqliteClientSubnetRepository::new(pool.clone()));
    let managed_domain_repo = Arc::new(SqliteManagedDomainRepository::new(pool.clone()));
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let null_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(NullBlockFilterEngine);

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
        get_stats: Arc::new(GetQueryStatsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
        ))),
        get_queries: Arc::new(GetRecentQueriesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
        ))),
        get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
        ))),
        get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
        get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
        create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
        update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
        delete_group: Arc::new(DeleteGroupUseCase::new(group_repo.clone())),
        assign_client_group: Arc::new(AssignClientGroupUseCase::new(client_repo.clone(), group_repo.clone())),
        get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(subnet_repo.clone())),
        create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(subnet_repo.clone(), group_repo.clone())),
        delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(subnet_repo.clone())),
        create_manual_client: Arc::new(CreateManualClientUseCase::new(client_repo.clone(), group_repo.clone())),
        update_client: Arc::new(UpdateClientUseCase::new(client_repo.clone())),
        delete_client: Arc::new(DeleteClientUseCase::new(client_repo.clone())),
        get_blocklist_sources: Arc::new(GetBlocklistSourcesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
        ))),
        create_blocklist_source: Arc::new(CreateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            group_repo.clone(),
        )),
        delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(Arc::new(
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
        get_managed_domains: Arc::new(GetManagedDomainsUseCase::new(managed_domain_repo.clone())),
        create_managed_domain: Arc::new(CreateManagedDomainUseCase::new(
            managed_domain_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        update_managed_domain: Arc::new(UpdateManagedDomainUseCase::new(
            managed_domain_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        delete_managed_domain: Arc::new(DeleteManagedDomainUseCase::new(
            managed_domain_repo.clone(),
            null_engine.clone(),
        )),
        get_regex_filters: Arc::new(ferrous_dns_application::use_cases::GetRegexFiltersUseCase::new(
            regex_filter_repo.clone(),
        )),
        create_regex_filter: Arc::new(ferrous_dns_application::use_cases::CreateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        update_regex_filter: Arc::new(ferrous_dns_application::use_cases::UpdateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        delete_regex_filter: Arc::new(ferrous_dns_application::use_cases::DeleteRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            null_engine.clone(),
        )),
        subnet_matcher: Arc::new(SubnetMatcherService::new(subnet_repo.clone())),
        get_timeline: Arc::new(ferrous_dns_application::use_cases::GetTimelineUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
        ))),
        get_query_rate: Arc::new(ferrous_dns_application::use_cases::GetQueryRateUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
        ))),
        get_cache_stats: Arc::new(ferrous_dns_application::use_cases::GetCacheStatsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
        ))),
        get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
        config: config.clone(),
        cache,
        dns_resolver: Arc::new(HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap()),
        api_key: None,
    };

    let app = create_api_routes(state);
    (app, config)
}

#[tokio::test]
async fn test_list_local_records_returns_empty_list() {
    let (app, _config) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_list_local_records_returns_preloaded_records() {
    let (app, config) = create_test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: Some("local".to_string()),
            ip: "192.168.1.10".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "ipv6host".to_string(),
            domain: None,
            ip: "::1".to_string(),
            record_type: "AAAA".to_string(),
            ttl: None,
        });
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 2);
    assert_eq!(json[0]["hostname"], "server");
    assert_eq!(json[0]["ip"], "192.168.1.10");
    assert_eq!(json[0]["record_type"], "A");
    assert_eq!(json[0]["ttl"], 300);
    assert_eq!(json[0]["fqdn"], "server.local");
    assert_eq!(json[1]["hostname"], "ipv6host");
    assert_eq!(json[1]["record_type"], "AAAA");
    assert_eq!(json[1]["ttl"], 300);
}

#[tokio::test]
async fn test_create_local_record_with_invalid_ip_returns_bad_request() {
    let (app, _config) = create_test_app().await;

    let payload = json!({
        "hostname": "myserver",
        "ip": "not-an-ip-address",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_local_record_with_invalid_record_type_returns_bad_request() {
    let (app, _config) = create_test_app().await;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "MX"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_local_record_with_invalid_ip_returns_bad_request() {
    let (app, _config) = create_test_app().await;

    let payload = json!({
        "hostname": "myserver",
        "ip": "bad-ip",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/0")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_local_record_with_invalid_record_type_returns_bad_request() {
    let (app, _config) = create_test_app().await;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "CNAME"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/0")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_local_record_not_found_returns_not_found() {
    let (app, _config) = create_test_app().await;

    let payload = json!({
        "hostname": "myserver",
        "ip": "10.0.0.1",
        "record_type": "A"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_local_record_not_found_returns_not_found() {
    let (app, _config) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_local_records_fqdn_without_domain_uses_hostname() {
    let (app, config) = create_test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "standalone".to_string(),
            domain: None,
            ip: "10.10.10.1".to_string(),
            record_type: "A".to_string(),
            ttl: Some(60),
        });
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/local-records")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json[0]["fqdn"], "standalone");
    assert_eq!(json[0]["ttl"], 60);
}
