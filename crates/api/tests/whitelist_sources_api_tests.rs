use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office"]).build().await
}

#[tokio::test]
async fn test_get_all_whitelist_sources_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
async fn test_create_whitelist_source_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Safe Sites Allowlist",
        "url": "https://example.com/allow.txt",
        "group_id": 1,
        "comment": "Main allow list",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
    assert_eq!(json["name"], "Safe Sites Allowlist");
    assert_eq!(json["url"], "https://example.com/allow.txt");
    assert_eq!(json["group_ids"][0], 1);
    assert_eq!(json["comment"], "Main allow list");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_whitelist_source_defaults() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Minimal Allowlist" });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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

    assert_eq!(json["name"], "Minimal Allowlist");
    assert_eq!(json["group_ids"][0], 1);
    assert_eq!(json["enabled"], true);
    assert!(json["url"].is_null());
}

#[tokio::test]
async fn test_create_whitelist_source_duplicate_name() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Duplicate Allowlist" });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
                .uri("/whitelist-sources")
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
async fn test_create_whitelist_source_invalid_url() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad URL Allowlist",
        "url": "ftp://not-http.com/allow.txt"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
async fn test_create_whitelist_source_invalid_group() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Group Allowlist",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_whitelist_source_by_id() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Get By ID Allowlist" });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
                .uri(format!("/whitelist-sources/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "Get By ID Allowlist");
}

#[tokio::test]
async fn test_get_whitelist_source_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_whitelist_source_toggle_enabled() {
    let app = test_app().await.router;

    let payload = json!({ "name": "Toggle Allowlist", "enabled": true });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
                .uri(format!("/whitelist-sources/{}", id))
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
async fn test_update_whitelist_source_not_found() {
    let app = test_app().await.router;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources/999")
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
async fn test_delete_whitelist_source_success() {
    let app = test_app().await.router;

    let payload = json!({ "name": "To Delete Allowlist" });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
                .uri(format!("/whitelist-sources/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_whitelist_source_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_whitelist_sources_after_create() {
    let app = test_app().await.router;

    let sources = vec![
        json!({"name": "Allowlist A", "url": "https://example.com/a.txt"}),
        json!({"name": "Allowlist B", "group_id": 2}),
    ];

    for source in &sources {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/whitelist-sources")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(source).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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
}

#[tokio::test]
async fn test_create_whitelist_source_has_null_last_synced_at() {
    let app = test_app().await.router;

    let payload =
        json!({ "name": "Never Synced Allowlist", "url": "https://example.com/allow.txt" });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/whitelist-sources")
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

    // The key must exist so a rename cannot pass silently, and it must be null
    // because the source has never been fetched.
    assert!(json.get("last_synced_at").is_some());
    assert!(json["last_synced_at"].is_null());
}
