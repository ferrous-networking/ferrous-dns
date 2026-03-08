mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /groups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_groups_returns_default_group() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/groups")
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

    let groups = json["groups"].as_array().expect("groups must be an array");
    assert!(
        !groups.is_empty(),
        "groups array must contain at least the default group"
    );

    let first = &groups[0];
    assert_eq!(first["name"], "Protected");
    assert_eq!(first["enabled"], true);
}

#[tokio::test]
async fn list_groups_response_has_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/groups")
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

    let groups = json["groups"].as_array().expect("groups must be an array");
    for group in groups {
        assert!(group["id"].is_number(), "group.id must be a number");
        assert!(group["name"].is_string(), "group.name must be a string");
        assert!(
            group["enabled"].is_boolean(),
            "group.enabled must be a boolean"
        );
    }
}

// ---------------------------------------------------------------------------
// POST /groups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_group_returns_created_status() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "name": "TestGroup" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
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

    assert_eq!(json["name"], "TestGroup");
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn create_group_with_comment() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "name": "WithComment", "comment": "test comment" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
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

    assert_eq!(json["comment"], "test comment");
}

#[tokio::test]
async fn create_duplicate_group_returns_conflict() {
    let pool = helpers::create_test_db().await;

    // First creation should succeed
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "Dup" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Second creation with same name should return 409 or 422
    let app = helpers::create_pihole_test_app(pool, None).await;
    let body = serde_json::json!({ "name": "Dup" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let status = response.status();
    assert!(
        status == StatusCode::CONFLICT || status == StatusCode::UNPROCESSABLE_ENTITY,
        "duplicate group must return 409 or 422, got {status}"
    );
}

// ---------------------------------------------------------------------------
// GET /groups/:name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_group_by_name_returns_matching_group() {
    let pool = helpers::create_test_db().await;

    // Create the group first
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "Lookup" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Retrieve it by name
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/groups/Lookup")
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

    assert_eq!(json["name"], "Lookup");
}

#[tokio::test]
async fn get_nonexistent_group_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/groups/NoSuchGroup")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// PUT /groups/:name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_group_changes_comment() {
    let pool = helpers::create_test_db().await;

    // Create group
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "Upd" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Update it
    let app = helpers::create_pihole_test_app(pool, None).await;
    let body = serde_json::json!({ "comment": "updated" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/groups/Upd")
                .header("content-type", "application/json")
                .body(Body::from(body))
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

    assert_eq!(json["comment"], "updated");
}

// ---------------------------------------------------------------------------
// DELETE /groups/:name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_returns_no_content() {
    let pool = helpers::create_test_db().await;

    // Create group
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "DelMe" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
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
                .uri("/groups/DelMe")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_nonexistent_group_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/groups/Ghost")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST /groups:batchDelete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_delete_groups_removes_specified_groups() {
    let pool = helpers::create_test_db().await;

    // Create B1
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "B1" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Create B2
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "name": "B2" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Batch delete both
    let app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "items": ["B1", "B2"] }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/groups:batchDelete")
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
                .uri("/groups")
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

    let groups = json["groups"].as_array().expect("groups must be an array");
    let names: Vec<&str> = groups.iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(
        !names.contains(&"B1"),
        "B1 must not be present after batch delete"
    );
    assert!(
        !names.contains(&"B2"),
        "B2 must not be present after batch delete"
    );
}
