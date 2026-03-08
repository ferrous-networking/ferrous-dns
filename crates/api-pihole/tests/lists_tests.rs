mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /lists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_all_returns_empty_array_on_fresh_database() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/lists")
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

    let lists = json["lists"].as_array().expect("lists must be an array");
    assert!(lists.is_empty(), "lists must be empty on a fresh database");
}

#[tokio::test]
async fn list_all_includes_created_list() {
    let pool = helpers::create_test_db().await;

    // Create a blocklist.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://block.list/hosts" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // List all and verify the created one appears.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let response = app2
        .oneshot(
            Request::builder()
                .uri("/lists")
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

    let lists = json["lists"].as_array().expect("lists must be an array");
    assert!(!lists.is_empty(), "lists must not be empty after creation");

    let found = lists
        .iter()
        .any(|l| l["address"].as_str() == Some("https://block.list/hosts"));
    assert!(found, "https://block.list/hosts must appear in the lists");
}

// ---------------------------------------------------------------------------
// POST /lists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_blocklist_returns_created() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "address": "https://block.list/hosts" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
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

    assert_eq!(json["address"], "https://block.list/hosts");
    assert_eq!(json["type"], 0);
}

#[tokio::test]
async fn create_whitelist_returns_created() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "address": "https://white.list/hosts", "type": 1 }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
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

    assert_eq!(json["type"], 1);
}

#[tokio::test]
async fn create_list_with_comment() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({
        "address": "https://commented.list",
        "comment": "my list"
    })
    .to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
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

    assert_eq!(json["comment"], "my list");
}

// ---------------------------------------------------------------------------
// GET /lists/:id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_list_by_id_returns_matching_list() {
    let pool = helpers::create_test_db().await;

    // Create a list and capture its id.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://by-id.list/hosts" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let create_bytes = create_response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_bytes).expect("invalid JSON");
    let id = created["id"]
        .as_i64()
        .expect("created list must have an id");

    // Fetch by id.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let response = app2
        .oneshot(
            Request::builder()
                .uri(format!("/lists/{id}"))
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

    assert_eq!(json["id"], id);
    assert_eq!(json["address"], "https://by-id.list/hosts");
}

#[tokio::test]
async fn get_nonexistent_list_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/lists/99999")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// PUT /lists/:id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_list_changes_address() {
    let pool = helpers::create_test_db().await;

    // Create a list.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://original.list" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let create_bytes = create_response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_bytes).expect("invalid JSON");
    let id = created["id"]
        .as_i64()
        .expect("created list must have an id");

    // Update the list address.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let update_body = serde_json::json!({ "address": "https://updated.list" }).to_string();
    let response = app2
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/lists/{id}"))
                .header("content-type", "application/json")
                .body(Body::from(update_body))
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

    assert_eq!(json["address"], "https://updated.list");
}

// ---------------------------------------------------------------------------
// DELETE /lists/:id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_list_returns_no_content() {
    let pool = helpers::create_test_db().await;

    // Create a list.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://delete-me.list" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let create_bytes = create_response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_bytes).expect("invalid JSON");
    let id = created["id"]
        .as_i64()
        .expect("created list must have an id");

    // Delete the list.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let response = app2
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/lists/{id}"))
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_nonexistent_list_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/lists/99999")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST /lists:batchDelete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_delete_lists_removes_specified() {
    let pool = helpers::create_test_db().await;

    // Create first list.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://batch1.list" }).to_string();
    let resp1 = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(resp1.status(), StatusCode::CREATED);
    let bytes1 = resp1
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let created1: Value = serde_json::from_slice(&bytes1).expect("invalid JSON");
    let id1 = created1["id"].as_i64().expect("first list must have an id");

    // Create second list.
    let app2 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "address": "https://batch2.list" }).to_string();
    let resp2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(resp2.status(), StatusCode::CREATED);
    let bytes2 = resp2
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let created2: Value = serde_json::from_slice(&bytes2).expect("invalid JSON");
    let id2 = created2["id"]
        .as_i64()
        .expect("second list must have an id");

    // Batch delete both (IDs as strings per Pi-hole v6 API).
    let app3 = helpers::create_pihole_test_app(pool, None).await;
    let delete_body =
        serde_json::json!({ "items": [id1.to_string(), id2.to_string()] }).to_string();
    let response = app3
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/lists:batchDelete")
                .header("content-type", "application/json")
                .body(Body::from(delete_body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
