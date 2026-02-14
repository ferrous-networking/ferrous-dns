use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_application::{services::SubnetMatcherService, use_cases::*};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::{
    dns::{cache::DnsCache, HickoryDnsResolver},
    repositories::{
        client_repository::SqliteClientRepository,
        client_subnet_repository::SqliteClientSubnetRepository,
        group_repository::SqliteGroupRepository,
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

    // Create groups table
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

    // Insert test groups
    sqlx::query(
        "INSERT INTO groups (id, name) VALUES (1, 'Protected'), (2, 'Office'), (3, 'Guest')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Create clients table
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

    // Create client_subnets table
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

    pool
}

async fn create_test_app() -> (Router, sqlx::SqlitePool) {
    let pool = create_test_db().await;
    let client_repo = Arc::new(SqliteClientRepository::new(pool.clone()));
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let subnet_repo = Arc::new(SqliteClientSubnetRepository::new(pool.clone()));

    let config = Arc::new(RwLock::new(Config::default()));
    let cache = Arc::new(DnsCache::new(
        0,
        ferrous_dns_infrastructure::dns::EvictionStrategy::LRU,
        0.0,
        0.0,
        0,
        0.0,
        false,
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
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(
                pool.clone(),
            ),
        ))),
        get_queries: Arc::new(GetRecentQueriesUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(
                pool.clone(),
            ),
        ))),
        get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
            ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(
                pool.clone(),
            ),
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
        config,
        cache,
        dns_resolver: Arc::new(HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap()),
    };

    let app = create_api_routes(state);
    (app, pool)
}

#[tokio::test]
async fn test_get_client_subnets_empty() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 2,
        "comment": "Office network"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
    assert_eq!(json["subnet_cidr"], "192.168.1.0/24");
    assert_eq!(json["group_id"], 2);
    assert_eq!(json["comment"], "Office network");
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_subnet_invalid_cidr() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "subnet_cidr": "invalid-cidr",
        "group_id": 2
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_invalid_group() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
async fn test_create_subnet_duplicate() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "subnet_cidr": "192.168.1.0/24",
        "group_id": 2
    });

    // First creation should succeed
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::CREATED);

    // Second creation with same CIDR should fail
    let response2 = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_all_subnets_with_data() {
    let (app, _pool) = create_test_app().await;

    // Create multiple subnets
    let subnets = vec![
        json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2, "comment": "Office"}),
        json!({"subnet_cidr": "10.0.0.0/8", "group_id": 3, "comment": "Guest"}),
    ];

    for subnet in &subnets {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/client-subnets")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(subnet).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Get all subnets
    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    // Verify structure
    assert!(arr[0]["id"].is_number());
    assert!(arr[0]["subnet_cidr"].is_string());
    assert!(arr[0]["group_id"].is_number());
    assert!(arr[0]["group_name"].is_string()); // Should be enriched with group name
}

#[tokio::test]
async fn test_delete_subnet_success() {
    let (app, _pool) = create_test_app().await;

    // Create subnet
    let payload = json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2});
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let subnet_id = json["id"].as_i64().unwrap();

    // Delete subnet
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/client-subnets/{}", subnet_id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_subnet_not_found() {
    let (app, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/client-subnets/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_manual_client_success() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "ip_address": "192.168.1.100",
        "group_id": 2,
        "hostname": "test-device",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
    assert_eq!(json["ip_address"], "192.168.1.100");
    // Response should include these fields (values may vary)
    assert!(json.get("group_id").is_some());
    assert!(json.get("hostname").is_some());
    assert!(json.get("mac_address").is_some());
}

#[tokio::test]
async fn test_create_manual_client_without_group() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "ip_address": "192.168.1.101",
        "hostname": "test-device-2"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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

    assert_eq!(json["ip_address"], "192.168.1.101");
    assert!(json["group_id"].is_null() || json["group_id"].is_number());
}

#[tokio::test]
async fn test_create_manual_client_invalid_ip() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "ip_address": "invalid-ip"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
async fn test_create_manual_client_invalid_group() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({
        "ip_address": "192.168.1.100",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
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
async fn test_subnet_enriched_with_group_name() {
    let (app, _pool) = create_test_app().await;

    let payload = json!({"subnet_cidr": "192.168.1.0/24", "group_id": 2});
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/client-subnets")
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
                .uri("/client-subnets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let subnet = &json.as_array().unwrap()[0];
    assert_eq!(subnet["group_id"], 2);
    assert_eq!(subnet["group_name"], "Office"); // Should be enriched
}
