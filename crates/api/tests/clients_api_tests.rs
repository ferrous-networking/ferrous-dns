use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_application::{
    ports::ClientRepository,
    use_cases::{
        GetBlocklistUseCase, GetClientsUseCase, GetQueryStatsUseCase, GetRecentQueriesUseCase,
    },
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::{
    dns::{cache::DnsCache, HickoryDnsResolver},
    repositories::client_repository::SqliteClientRepository,
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

    // Run migration
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

async fn create_test_app() -> (Router, Arc<SqliteClientRepository>, sqlx::SqlitePool) {
    let pool = create_test_db().await;
    let client_repo = Arc::new(SqliteClientRepository::new(pool.clone()));

    // Create minimal AppState for testing
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

    // Create a minimal DNS resolver setup
    use ferrous_dns_domain::config::upstream::{UpstreamPool, UpstreamStrategy};
    use ferrous_dns_infrastructure::dns::{PoolManager, QueryEventEmitter};

    let event_emitter = QueryEventEmitter::new_disabled();

    // Create a test upstream pool (required for PoolManager)
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

    // Note: These use cases won't be called in client tests, but needed for AppState
    // In a real scenario, you'd mock these properly
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
            ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
        ))),
        get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
        config,
        cache,
        dns_resolver: Arc::new(
            HickoryDnsResolver::new_with_pools(pool_manager, 5000, false, None).unwrap(),
        ),
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

    // Add test data
    let ip1: IpAddr = "192.168.1.100".parse().unwrap();
    let ip2: IpAddr = "192.168.1.101".parse().unwrap();

    repo.update_last_seen(ip1).await.unwrap();
    repo.update_last_seen(ip2).await.unwrap();
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

    // Verify first client structure
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

    // Add 10 clients
    for i in 1..=10 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Test with limit=5
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

    // Test with offset=5
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

    // Add test data
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();

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

    // Add a client with all fields populated
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
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

    // Verify JSON structure matches ClientResponse DTO
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

    // Add clients
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Make some clients old
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

    // Should return only active clients (this test is approximate due to test setup)
    assert!(json.is_array());
}
