use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_application::{
    ports::{
        BlockFilterEnginePort, BlockedServiceRepository, ClientRepository, FilterDecision,
        ServiceCatalogPort,
    },
    use_cases::{
        DeleteClientUseCase, GetBlockFilterStatsUseCase, GetBlocklistUseCase, GetClientsUseCase,
        GetQueryStatsUseCase, GetRecentQueriesUseCase, UpdateClientUseCase,
    },
};

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
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
}

struct NullBlockedServiceRepository;

#[async_trait::async_trait]
impl BlockedServiceRepository for NullBlockedServiceRepository {
    async fn block_service(
        &self,
        _service_id: &str,
        _group_id: i64,
    ) -> Result<ferrous_dns_domain::BlockedService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn unblock_service(
        &self,
        _service_id: &str,
        _group_id: i64,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn get_blocked_for_group(
        &self,
        _group_id: i64,
    ) -> Result<Vec<ferrous_dns_domain::BlockedService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn get_all_blocked(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::BlockedService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn delete_all_for_service(
        &self,
        _service_id: &str,
    ) -> Result<u64, ferrous_dns_domain::DomainError> {
        Ok(0)
    }
}

struct NullCustomServiceRepository;

#[async_trait::async_trait]
impl ferrous_dns_application::ports::CustomServiceRepository for NullCustomServiceRepository {
    async fn create(
        &self,
        _service_id: &str,
        _name: &str,
        _category_name: &str,
        _domains: &[String],
    ) -> Result<ferrous_dns_domain::CustomService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn get_by_service_id(
        &self,
        _service_id: &str,
    ) -> Result<Option<ferrous_dns_domain::CustomService>, ferrous_dns_domain::DomainError> {
        Ok(None)
    }
    async fn get_all(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::CustomService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _service_id: &str,
        _name: Option<String>,
        _category_name: Option<String>,
        _domains: Option<Vec<String>>,
    ) -> Result<ferrous_dns_domain::CustomService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn delete(&self, _service_id: &str) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

struct NullServiceCatalog;

impl ServiceCatalogPort for NullServiceCatalog {
    fn get_by_id(&self, _id: &str) -> Option<ferrous_dns_domain::ServiceDefinition> {
        None
    }
    fn all(&self) -> Vec<ferrous_dns_domain::ServiceDefinition> {
        vec![]
    }
    fn normalized_rules_for(&self, _service_id: &str) -> Vec<String> {
        vec![]
    }
    fn reload_custom(&self, _custom: Vec<ferrous_dns_domain::ServiceDefinition>) {}
}

use ferrous_dns_domain::{config::DatabaseConfig, Config};
use ferrous_dns_infrastructure::{
    dns::{cache::DnsCache, HickoryDnsResolver},
    repositories::{
        client_repository::SqliteClientRepository,
        regex_filter_repository::SqliteRegexFilterRepository,
    },
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

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
        VALUES (1, 'Protected', 1, 'Default group for all clients. Cannot be disabled or deleted.', 1)
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

    pool
}

async fn create_test_app() -> (Router, Arc<SqliteClientRepository>, sqlx::SqlitePool) {
    let pool = create_test_db().await;
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
            .await
            .expect("Failed to create PoolManager"),
    );

    let state = AppState {
        get_stats: Arc::new(GetQueryStatsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(
                pool.clone(), pool.clone(), &DatabaseConfig::default(),
            ),
        ))),
        get_queries: Arc::new(GetRecentQueriesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(
                pool.clone(), pool.clone(), &DatabaseConfig::default(),
            ),
        ))),
        get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
        ))),
        get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
        get_groups: Arc::new(ferrous_dns_application::use_cases::GetGroupsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone()),
        ))),
        create_group: Arc::new(ferrous_dns_application::use_cases::CreateGroupUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone()),
        ))),
        update_group: Arc::new(ferrous_dns_application::use_cases::UpdateGroupUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone()),
        ))),
        delete_group: Arc::new(ferrous_dns_application::use_cases::DeleteGroupUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone()),
        ))),
        assign_client_group: Arc::new(ferrous_dns_application::use_cases::AssignClientGroupUseCase::new(
            client_repo.clone(),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        get_client_subnets: Arc::new(ferrous_dns_application::use_cases::GetClientSubnetsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
        ))),
        create_client_subnet: Arc::new(ferrous_dns_application::use_cases::CreateClientSubnetUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        delete_client_subnet: Arc::new(ferrous_dns_application::use_cases::DeleteClientSubnetUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
        ))),
        create_manual_client: Arc::new(ferrous_dns_application::use_cases::CreateManualClientUseCase::new(
            client_repo.clone(),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        update_client: Arc::new(UpdateClientUseCase::new(client_repo.clone())),
        delete_client: Arc::new(DeleteClientUseCase::new(client_repo.clone())),
        get_blocklist_sources: Arc::new(ferrous_dns_application::use_cases::GetBlocklistSourcesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
        ))),
        create_blocklist_source: Arc::new(ferrous_dns_application::use_cases::CreateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        update_blocklist_source: Arc::new(ferrous_dns_application::use_cases::UpdateBlocklistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
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
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        update_whitelist_source: Arc::new(ferrous_dns_application::use_cases::UpdateWhitelistSourceUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
        )),
        delete_whitelist_source: Arc::new(ferrous_dns_application::use_cases::DeleteWhitelistSourceUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone()),
        ))),
        get_managed_domains: Arc::new(ferrous_dns_application::use_cases::GetManagedDomainsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone()),
        ))),
        create_managed_domain: Arc::new(ferrous_dns_application::use_cases::CreateManagedDomainUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
            Arc::new(NullBlockFilterEngine),
        )),
        update_managed_domain: Arc::new(ferrous_dns_application::use_cases::UpdateManagedDomainUseCase::new(
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            Arc::new(ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(pool.clone())),
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
        get_service_catalog: Arc::new(ferrous_dns_application::use_cases::GetServiceCatalogUseCase::new(Arc::new(NullServiceCatalog))),
        get_blocked_services: Arc::new(ferrous_dns_application::use_cases::GetBlockedServicesUseCase::new(Arc::new(NullBlockedServiceRepository))),
        block_service: Arc::new(ferrous_dns_application::use_cases::BlockServiceUseCase::new(
            Arc::new(NullBlockedServiceRepository),
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            group_repo.clone(),
            Arc::new(NullBlockFilterEngine),
            Arc::new(NullServiceCatalog),
        )),
        unblock_service: Arc::new(ferrous_dns_application::use_cases::UnblockServiceUseCase::new(
            Arc::new(NullBlockedServiceRepository),
            Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
            Arc::new(NullBlockFilterEngine),
        )),
        create_custom_service: Arc::new(ferrous_dns_application::use_cases::CreateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog))),
        get_custom_services: Arc::new(ferrous_dns_application::use_cases::GetCustomServicesUseCase::new(Arc::new(NullCustomServiceRepository))),
        update_custom_service: Arc::new(ferrous_dns_application::use_cases::UpdateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())), Arc::new(NullBlockedServiceRepository), Arc::new(NullBlockFilterEngine))),
        delete_custom_service: Arc::new(ferrous_dns_application::use_cases::DeleteCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(NullBlockedServiceRepository), Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())), Arc::new(NullBlockFilterEngine))),
        config,
        cache,
        dns_resolver: Arc::new(
            HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap(),
        ),
        api_key: None,
    };

    let app = create_api_routes(state);
    (app, client_repo, pool)
}

#[tokio::test]
async fn test_get_clients_empty() {
    let (app, _repo, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
async fn test_get_clients_with_data() {
    let (app, repo, _pool) = create_test_app().await;

    let ip1: IpAddr = "192.168.1.100".parse().unwrap();
    let ip2: IpAddr = "192.168.1.101".parse().unwrap();

    repo.update_last_seen(ip1).await.unwrap();
    repo.update_last_seen(ip2).await.unwrap();
    repo.flush_writes().await;
    repo.update_mac_address(ip1, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip1, "device1.local".to_string())
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    let clients = json.as_array().unwrap();
    assert_eq!(clients.len(), 2);

    let client = &clients[0];
    assert!(client.get("id").is_some());
    assert!(client.get("ip_address").is_some());
    assert!(client.get("mac_address").is_some());
    assert!(client.get("hostname").is_some());
    assert!(client.get("first_seen").is_some());
    assert!(client.get("last_seen").is_some());
    assert!(client.get("query_count").is_some());
}

#[tokio::test]
async fn test_get_clients_with_pagination() {
    let (app, repo, _pool) = create_test_app().await;

    for i in 1..=10 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }
    repo.flush_writes().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/clients?limit=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 5);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients?limit=5&offset=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_get_client_stats() {
    let (app, repo, _pool) = create_test_app().await;

    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
        repo.flush_writes().await;

        if i <= 3 {
            repo.update_mac_address(ip, format!("aa:bb:cc:dd:ee:{:02x}", i))
                .await
                .unwrap();
        }

        if i <= 2 {
            repo.update_hostname(ip, format!("device{}.local", i))
                .await
                .unwrap();
        }
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_clients"], 5);
    assert_eq!(json["with_mac"], 3);
    assert_eq!(json["with_hostname"], 2);
    assert!(json.get("active_24h").is_some());
    assert!(json.get("active_7d").is_some());
}

#[tokio::test]
async fn test_get_clients_json_structure() {
    let (app, repo, _pool) = create_test_app().await;

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.flush_writes().await;
    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip, "test-device.local".to_string())
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let client = &json.as_array().unwrap()[0];

    assert!(client["id"].is_number());
    assert_eq!(client["ip_address"], "192.168.1.100");
    assert_eq!(client["mac_address"], "aa:bb:cc:dd:ee:ff");
    assert_eq!(client["hostname"], "test-device.local");
    assert!(client["first_seen"].is_string());
    assert!(client["last_seen"].is_string());
    assert_eq!(client["query_count"], 1);
}

#[tokio::test]
async fn test_get_clients_with_active_days_filter() {
    let (app, repo, pool) = create_test_app().await;

    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-31 days') WHERE ip_address = '192.168.1.1'",
    )
    .execute(&pool)
    .await
    .ok();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients?active_days=30")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
}

#[tokio::test]
async fn test_delete_client_success() {
    let (app, repo, _pool) = create_test_app().await;

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.flush_writes().await;

    let clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(clients.len(), 1);
    let client_id = clients[0].id.unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", client_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 0);
}

#[tokio::test]
async fn test_delete_nonexistent_client() {
    let (app, _repo, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/clients/9999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_msg = String::from_utf8_lossy(&body);
    assert!(error_msg.contains("not found") || error_msg.contains("9999"));
}

#[tokio::test]
async fn test_delete_client_with_complete_data() {
    let (app, repo, _pool) = create_test_app().await;

    let ip: IpAddr = "192.168.1.200".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.flush_writes().await;
    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip, "test-device.local".to_string())
        .await
        .unwrap();

    let clients = repo.get_all(100, 0).await.unwrap();
    let client_id = clients[0].id.unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", client_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 0);
}

#[tokio::test]
async fn test_delete_client_from_multiple() {
    let (app, repo, _pool) = create_test_app().await;

    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }
    repo.flush_writes().await;

    let clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(clients.len(), 3);

    let client_id = clients[1].id.unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", client_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(!remaining.iter().any(|c| c.id == Some(client_id)));
}

#[tokio::test]
async fn test_delete_client_idempotency() {
    let (app, repo, _pool) = create_test_app().await;

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.flush_writes().await;

    let clients = repo.get_all(100, 0).await.unwrap();
    let client_id = clients[0].id.unwrap();

    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", client_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::NO_CONTENT);

    let response2 = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", client_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_client_invalid_id_format() {
    let (app, _repo, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/clients/not-a-number")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_delete_multiple_clients_sequentially() {
    let (app, repo, _pool) = create_test_app().await;

    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }
    repo.flush_writes().await;

    let mut clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(clients.len(), 5);

    for _ in 0..3 {
        let client_id = clients.pop().unwrap().id.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/clients/{}", client_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn test_delete_client_verifies_not_in_get_all() {
    let (app, repo, _pool) = create_test_app().await;

    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }
    repo.flush_writes().await;

    let clients_before = repo.get_all(100, 0).await.unwrap();
    let delete_id = clients_before[1].id.unwrap();
    let delete_ip = clients_before[1].ip_address;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/clients/{}", delete_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);

    let body = get_response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let clients_after = json.as_array().unwrap();

    assert_eq!(clients_after.len(), 2);

    assert!(!clients_after
        .iter()
        .any(|c| c["ip_address"].as_str().unwrap() == delete_ip.to_string()));
}
