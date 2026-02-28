use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{
    create_api_routes, AppState, BlockingUseCases, ClientUseCases, DnsUseCases, GroupUseCases,
    QueryUseCases, ServiceUseCases,
};
use ferrous_dns_application::{
    ports::{
        BlockFilterEnginePort, BlockedServiceRepository, ConfigRepository, FilterDecision,
        ServiceCatalogPort,
    },
    services::SubnetMatcherService,
    use_cases::{GetBlockFilterStatsUseCase, *},
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
struct NullConfigRepository;
#[async_trait::async_trait]
impl ConfigRepository for NullConfigRepository {
    async fn get_config(&self) -> Result<Config, ferrous_dns_domain::DomainError> {
        Ok(Config::default())
    }
    async fn save_config(&self, _config: &Config) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn save_local_records(
        &self,
        _config: &Config,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

use ferrous_dns_domain::{config::DatabaseConfig, Config};
use ferrous_dns_infrastructure::{
    dns::cache::DnsCache,
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
            service_id TEXT,
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

async fn create_test_app() -> (Router, sqlx::SqlitePool) {
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
            .await
            .expect("Failed to create PoolManager"),
    );

    let state = AppState {
        query: QueryUseCases {
            get_stats: Arc::new(GetQueryStatsUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
            ), client_repo.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), &DatabaseConfig::default()),
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
        },
        dns: DnsUseCases {
            cache: cache as Arc<dyn ferrous_dns_application::ports::DnsCachePort>,
            create_local_record: Arc::new(CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            update_local_record: Arc::new(UpdateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            delete_local_record: Arc::new(DeleteLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            upstream_health: Arc::new(ferrous_dns_infrastructure::dns::UpstreamHealthAdapter::new(
                pool_manager,
                None,
            )),
        },
        groups: GroupUseCases {
            get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
            create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
            update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
            delete_group: Arc::new(DeleteGroupUseCase::new(group_repo.clone())),
            assign_client_group: Arc::new(AssignClientGroupUseCase::new(client_repo.clone(), group_repo.clone())),
        },
        clients: ClientUseCases {
            get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
            get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(subnet_repo.clone())),
            create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(subnet_repo.clone(), group_repo.clone())),
            delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(subnet_repo.clone())),
            create_manual_client: Arc::new(CreateManualClientUseCase::new(client_repo.clone(), group_repo.clone())),
            update_client: Arc::new(UpdateClientUseCase::new(client_repo.clone())),
            delete_client: Arc::new(DeleteClientUseCase::new(client_repo.clone())),
            subnet_matcher: Arc::new(SubnetMatcherService::new(subnet_repo.clone())),
        },
        blocking: BlockingUseCases {
            get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
            ))),
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
            get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
        },
        services: ServiceUseCases {
            get_service_catalog: Arc::new(GetServiceCatalogUseCase::new(Arc::new(NullServiceCatalog))),
            get_blocked_services: Arc::new(GetBlockedServicesUseCase::new(Arc::new(NullBlockedServiceRepository))),
            block_service: Arc::new(BlockServiceUseCase::new(
                Arc::new(NullBlockedServiceRepository),
                managed_domain_repo.clone(),
                group_repo.clone(),
                null_engine.clone(),
                Arc::new(NullServiceCatalog),
            )),
            unblock_service: Arc::new(UnblockServiceUseCase::new(
                Arc::new(NullBlockedServiceRepository),
                managed_domain_repo.clone(),
                null_engine.clone(),
            )),
            create_custom_service: Arc::new(ferrous_dns_application::use_cases::CreateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog))),
            get_custom_services: Arc::new(ferrous_dns_application::use_cases::GetCustomServicesUseCase::new(Arc::new(NullCustomServiceRepository))),
            update_custom_service: Arc::new(ferrous_dns_application::use_cases::UpdateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), managed_domain_repo.clone(), Arc::new(NullBlockedServiceRepository), null_engine.clone())),
            delete_custom_service: Arc::new(ferrous_dns_application::use_cases::DeleteCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(NullBlockedServiceRepository), managed_domain_repo.clone(), null_engine.clone())),
        },
        config: config.clone(),
        config_file_persistence: Arc::new(ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence),
        api_key: None,
    };

    let app = create_api_routes(state);
    (app, pool)
}

#[tokio::test]
async fn test_get_all_managed_domains_empty() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
}

#[tokio::test]
async fn test_create_managed_domain_deny_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Block Ads",
        "domain": "ads.example.com",
        "action": "deny",
        "group_id": 1,
        "comment": "Block ads domain",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id"].is_number());
    assert_eq!(json["name"], "Block Ads");
    assert_eq!(json["domain"], "ads.example.com");
    assert_eq!(json["action"], "deny");
    assert_eq!(json["group_id"], 1);
    assert_eq!(json["comment"], "Block ads domain");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_managed_domain_allow_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Allow Company",
        "domain": "mycompany.com",
        "action": "allow",
        "group_id": 1
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["action"], "allow");
    assert_eq!(json["enabled"], true);
    assert!(json["comment"].is_null());
}

#[tokio::test]
async fn test_create_managed_domain_invalid_action() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Bad Action",
        "domain": "ads.example.com",
        "action": "block"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
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
async fn test_create_managed_domain_duplicate_name() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Duplicate",
        "domain": "ads.example.com",
        "action": "deny"
    });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_create_managed_domain_invalid_group() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Bad Group",
        "domain": "ads.example.com",
        "action": "deny",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
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
async fn test_get_managed_domain_by_id() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Get By ID",
        "domain": "ads.example.com",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "Get By ID");
}

#[tokio::test]
async fn test_get_managed_domain_not_found() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_managed_domain_toggle_enabled() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Toggle Domain",
        "domain": "ads.example.com",
        "action": "deny",
        "enabled": true
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["enabled"], false);
}

#[tokio::test]
async fn test_update_managed_domain_not_found() {
    let (app, _pool) = create_test_app().await;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_managed_domain_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "To Delete",
        "domain": "ads.example.com",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_managed_domain_not_found() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_managed_domains_after_create() {
    let (app, _pool) = create_test_app().await;

    let domains = vec![
        json!({"name": "Domain A", "domain": "a.example.com", "action": "deny"}),
        json!({"name": "Domain B", "domain": "b.example.com", "action": "allow", "group_id": 2}),
    ];

    for domain in &domains {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/managed-domains")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(domain).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 2);
}
