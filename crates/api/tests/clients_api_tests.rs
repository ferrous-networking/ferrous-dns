use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_domain::HostnameSource;
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::IpAddr;
use tower::ServiceExt;

mod helpers;

#[tokio::test]
async fn test_get_clients_empty() {
    let app = TestApp::new().await.router;

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

    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_clients_with_data() {
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

    let ip1: IpAddr = "192.168.1.100".parse().unwrap();
    let ip2: IpAddr = "192.168.1.101".parse().unwrap();

    repo.update_last_seen(ip1).await.unwrap();
    repo.update_last_seen(ip2).await.unwrap();
    repo.flush_writes().await;
    repo.update_mac_address(ip1, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip1, "device1.local".to_string(), HostnameSource::Ptr)
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

    assert!(json["data"].is_array());
    let clients = json["data"].as_array().unwrap();
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
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
    assert_eq!(json["data"].as_array().unwrap().len(), 5);

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
    assert_eq!(json["data"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_get_client_stats() {
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
            repo.update_hostname(ip, format!("device{}.local", i), HostnameSource::Ptr)
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
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.flush_writes().await;
    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip, "test-device.local".to_string(), HostnameSource::Ptr)
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

    let client = &json["data"].as_array().unwrap()[0];

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
    let TestApp {
        router: app,
        client_repo: repo,
        pool,
        ..
    } = TestApp::new().await;

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

    assert!(json["data"].is_array());
}

#[tokio::test]
async fn test_delete_client_success() {
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
    let app = TestApp::new().await.router;

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
}

#[tokio::test]
async fn test_delete_client_from_multiple() {
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
async fn test_delete_multiple_clients_sequentially() {
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
    let TestApp {
        router: app,
        client_repo: repo,
        ..
    } = TestApp::new().await;

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
    let clients_after = json["data"].as_array().unwrap();

    assert_eq!(clients_after.len(), 2);

    assert!(!clients_after
        .iter()
        .any(|c| c["ip_address"].as_str().unwrap() == delete_ip.to_string()));
}
