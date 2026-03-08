mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /clients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_clients_returns_empty_array_on_fresh_database() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let clients = json["clients"]
        .as_array()
        .expect("clients must be an array");
    assert!(
        clients.is_empty(),
        "clients must be empty on fresh database"
    );
}

#[tokio::test]
async fn list_clients_returns_created_clients() {
    let pool = helpers::create_test_db().await;

    // Create a client via POST
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "192.168.1.99" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // List clients and verify it appears
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let clients = json["clients"]
        .as_array()
        .expect("clients must be an array");
    assert!(
        !clients.is_empty(),
        "clients must contain the created client"
    );

    let ips: Vec<&str> = clients.iter().filter_map(|c| c["ip"].as_str()).collect();
    assert!(
        ips.contains(&"192.168.1.99"),
        "created client IP must appear in the list"
    );
}

// ---------------------------------------------------------------------------
// POST /clients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_client_returns_created_status() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "ip": "192.168.1.50" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::CREATED);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert_eq!(json["ip"], "192.168.1.50");
}

#[tokio::test]
async fn create_client_with_group() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "ip": "10.0.0.5", "groups": [1] }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::CREATED);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let groups = json["groups"].as_array().expect("groups must be an array");
    let group_ids: Vec<i64> = groups.iter().filter_map(|g| g.as_i64()).collect();
    assert!(group_ids.contains(&1), "groups must contain group id 1");
}

#[tokio::test]
async fn create_client_with_invalid_ip_returns_error() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "ip": "not-an-ip" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    assert!(
        (400..500).contains(&status),
        "invalid IP must return a 4xx status, got {status}"
    );
}

// ---------------------------------------------------------------------------
// PUT /clients/:client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_client_changes_group() {
    let pool = helpers::create_test_db().await;

    // Create client
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "10.0.0.10" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Update client group
    let app = helpers::create_pihole_test_app(pool, None).await;
    let body = serde_json::json!({ "groups": [1] }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/clients/10.0.0.10")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// DELETE /clients/:client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_client_returns_no_content() {
    let pool = helpers::create_test_db().await;

    // Create client
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "10.0.0.20" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Delete it
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/clients/10.0.0.20")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_nonexistent_client_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/clients/99.99.99.99")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// GET /clients/_suggestions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suggestions_returns_suggestions_array() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients/_suggestions")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert!(
        json["suggestions"].is_array(),
        "response must have a 'suggestions' array field"
    );
}

#[tokio::test]
async fn suggestions_includes_created_client() {
    let pool = helpers::create_test_db().await;

    // Create a client
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "10.0.0.30" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get suggestions
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients/_suggestions")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let suggestions = json["suggestions"]
        .as_array()
        .expect("suggestions must be an array");
    let suggestion_strings: Vec<String> = suggestions
        .iter()
        .map(|s| s.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        suggestion_strings.iter().any(|s| s.contains("10.0.0.30")),
        "suggestions must include the created client IP, got: {suggestion_strings:?}"
    );
}

// ---------------------------------------------------------------------------
// POST /clients:batchDelete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_delete_clients_removes_specified() {
    let pool = helpers::create_test_db().await;

    // Create first client
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "10.0.0.40" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Create second client
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "ip": "10.0.0.41" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Batch delete both
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "items": ["10.0.0.40", "10.0.0.41"] }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients:batchDelete")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify they are gone
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/clients")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let clients = json["clients"]
        .as_array()
        .expect("clients must be an array");
    let ips: Vec<&str> = clients.iter().filter_map(|c| c["ip"].as_str()).collect();
    assert!(
        !ips.contains(&"10.0.0.40"),
        "10.0.0.40 must not be present after batch delete"
    );
    assert!(
        !ips.contains(&"10.0.0.41"),
        "10.0.0.41 must not be present after batch delete"
    );
}
