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

use ferrous_dns_domain::Config;
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

async fn create_test_app() -> (Router, sqlx::SqlitePool) {
    let pool = create_test_db().await;

    let client_repo = Arc::new(SqliteClientRepository::new(pool.clone()));
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
            lfuk_history_size: 0,
            batch_eviction_percentage: 0.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
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
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone()),
        ))),
        get_queries: Arc::new(GetRecentQueriesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone()),
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
        get_regex_filters: Arc::new(GetRegexFiltersUseCase::new(regex_filter_repo.clone())),
        create_regex_filter: Arc::new(CreateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        update_regex_filter: Arc::new(UpdateRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            group_repo.clone(),
            null_engine.clone(),
        )),
        delete_regex_filter: Arc::new(DeleteRegexFilterUseCase::new(
            regex_filter_repo.clone(),
            null_engine.clone(),
        )),
        subnet_matcher: Arc::new(SubnetMatcherService::new(subnet_repo.clone())),
        get_timeline: Arc::new(ferrous_dns_application::use_cases::GetTimelineUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone()),
        ))),
        get_query_rate: Arc::new(ferrous_dns_application::use_cases::GetQueryRateUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone()),
        ))),
        get_cache_stats: Arc::new(ferrous_dns_application::use_cases::GetCacheStatsUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone()),
        ))),
        get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
        config,
        cache,
        dns_resolver: Arc::new(HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap()),
    };

    let app = create_api_routes(state);
    (app, pool)
}

// ── GET /regex-filters (empty) ─────────────────────────────────────────────

#[tokio::test]
async fn test_get_all_regex_filters_empty() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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

// ── POST /regex-filters ────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_regex_filter_deny_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Block Ads",
        "pattern": "^ads\\..*\\.com$",
        "action": "deny",
        "group_id": 1,
        "comment": "Block ad domains",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
    assert_eq!(json["pattern"], "^ads\\..*\\.com$");
    assert_eq!(json["action"], "deny");
    assert_eq!(json["group_id"], 1);
    assert_eq!(json["comment"], "Block ad domains");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_regex_filter_allow_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Allow Safe",
        "pattern": "^safe\\.example\\.com$",
        "action": "allow",
        "group_id": 1
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
async fn test_create_regex_filter_defaults() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Defaults Test",
        "pattern": "tracker\\..*",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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

    assert_eq!(json["group_id"], 1);
    assert_eq!(json["enabled"], true);
    assert!(json["comment"].is_null());
}

#[tokio::test]
async fn test_create_regex_filter_invalid_pattern() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Bad Pattern",
        "pattern": "[invalid regex(",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
async fn test_create_regex_filter_duplicate_name() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Duplicate",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
                .uri("/regex-filters")
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
async fn test_create_regex_filter_invalid_action() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Bad Action",
        "pattern": "^ads\\..*",
        "action": "block"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
async fn test_create_regex_filter_invalid_group_id() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Bad Group",
        "pattern": "^ads\\..*",
        "action": "deny",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── GET /regex-filters/:id ─────────────────────────────────────────────────

#[tokio::test]
async fn test_get_regex_filter_by_id_found() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Get By ID",
        "pattern": "^tracker\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
                .uri(format!("/regex-filters/{}", id))
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
    assert_eq!(json["pattern"], "^tracker\\..*");
    assert_eq!(json["action"], "deny");
}

#[tokio::test]
async fn test_get_regex_filter_by_id_not_found() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── PUT /regex-filters/:id ─────────────────────────────────────────────────

#[tokio::test]
async fn test_update_regex_filter_toggle_enabled() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Toggle Filter",
        "pattern": "^ads\\..*",
        "action": "deny",
        "enabled": true
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
                .uri(format!("/regex-filters/{}", id))
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
async fn test_update_regex_filter_change_pattern() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Change Pattern",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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

    let update_payload = json!({ "pattern": "^tracker\\..*\\.com$" });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
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
    assert_eq!(json["pattern"], "^tracker\\..*\\.com$");
}

#[tokio::test]
async fn test_update_regex_filter_invalid_pattern() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Update Invalid",
        "pattern": "^valid\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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

    let update_payload = json!({ "pattern": "[invalid regex(" });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_update_regex_filter_not_found() {
    let (app, _pool) = create_test_app().await;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── DELETE /regex-filters/:id ──────────────────────────────────────────────

#[tokio::test]
async fn test_delete_regex_filter_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "To Delete",
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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
                .uri(format!("/regex-filters/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_regex_filter_not_found() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Multiple entries ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_all_regex_filters_multiple() {
    let (app, _pool) = create_test_app().await;

    let filters = vec![
        json!({"name": "Filter A", "pattern": "^ads\\..*", "action": "deny"}),
        json!({"name": "Filter B", "pattern": "^safe\\..*", "action": "allow", "group_id": 2}),
        json!({"name": "Filter C", "pattern": "^tracker\\..*", "action": "deny"}),
    ];

    for filter in &filters {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/regex-filters")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(filter).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 3);
}

// ── Validation edge cases ──────────────────────────────────────────────────

#[tokio::test]
async fn test_regex_filter_name_too_long() {
    let (app, _pool) = create_test_app().await;

    let long_name = "a".repeat(256);
    let payload = json!({
        "name": long_name,
        "pattern": "^ads\\..*",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_empty_pattern() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Empty Pattern",
        "pattern": "",
        "action": "deny"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_comment_too_long() {
    let (app, _pool) = create_test_app().await;

    let long_comment = "c".repeat(1001);
    let payload = json!({
        "name": "Long Comment",
        "pattern": "^ads\\..*",
        "action": "deny",
        "comment": long_comment
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected client error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_regex_filter_update_group() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "name": "Group Change",
        "pattern": "^ads\\..*",
        "action": "deny",
        "group_id": 1
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/regex-filters")
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

    let update_payload = json!({ "group_id": 2 });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/regex-filters/{}", id))
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
    assert_eq!(json["group_id"], 2);
}
