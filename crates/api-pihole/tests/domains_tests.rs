mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /domains
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_all_domains_returns_empty_array_on_fresh_database() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/domains")
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

    let domains = json["domains"]
        .as_array()
        .expect("domains must be an array");
    assert!(
        domains.is_empty(),
        "domains must be empty on a fresh database"
    );
}

#[tokio::test]
async fn list_all_domains_includes_created_exact_domain() {
    let pool = helpers::create_test_db().await;

    // Create a deny/exact domain first.
    let create_app = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "ads.example.com" }).to_string();
    let create_response = create_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/deny/exact")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // List all domains and verify the created one appears.
    let list_app = helpers::create_pihole_test_app(pool, None).await;
    let response = list_app
        .oneshot(
            Request::builder()
                .uri("/domains")
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

    let domains = json["domains"]
        .as_array()
        .expect("domains must be an array");
    assert!(
        !domains.is_empty(),
        "domains list must not be empty after creation"
    );

    let found = domains
        .iter()
        .any(|d| d["domain"].as_str() == Some("ads.example.com"));
    assert!(found, "ads.example.com must appear in the domains list");
}

// ---------------------------------------------------------------------------
// POST /domains/:type/:kind — create exact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_exact_deny_domain_returns_created() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "domain": "ads.example.com" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/deny/exact")
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

    assert_eq!(json["domain"], "ads.example.com");
    assert_eq!(json["type"], "deny");
    assert_eq!(json["kind"], "exact");
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn create_exact_allow_domain_returns_created() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "domain": "safe.com" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/allow/exact")
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

    assert_eq!(json["type"], "allow");
    assert_eq!(json["kind"], "exact");
}

// ---------------------------------------------------------------------------
// POST /domains/:type/:kind — create regex
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_regex_deny_domain_returns_created() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "domain": ".*\\.ads\\..*" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/deny/regex")
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

    assert_eq!(json["kind"], "regex");
    assert_eq!(json["type"], "deny");
}

// ---------------------------------------------------------------------------
// GET /domains/:type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_by_type_deny_returns_only_deny_entries() {
    let pool = helpers::create_test_db().await;

    // Create an allow domain.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "safe.com" }).to_string();
    app1.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/allow/exact")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // Create a deny domain.
    let app2 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "bad.com" }).to_string();
    app2.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/deny/exact")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // List only deny domains.
    let app3 = helpers::create_pihole_test_app(pool, None).await;
    let response = app3
        .oneshot(
            Request::builder()
                .uri("/domains/deny")
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

    let domains = json["domains"]
        .as_array()
        .expect("domains must be an array");
    for entry in domains {
        assert_eq!(
            entry["type"], "deny",
            "all entries returned by /domains/deny must have type == deny"
        );
    }
}

#[tokio::test]
async fn list_by_type_with_invalid_type_returns_unprocessable_entity() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/domains/invalid")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// GET /domains/:type/:kind
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_by_type_kind_returns_filtered_results() {
    let pool = helpers::create_test_db().await;

    // Create deny/exact.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "exact-deny.com" }).to_string();
    app1.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/deny/exact")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // Create deny/regex.
    let app2 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": ".*\\.tracker\\..*" }).to_string();
    app2.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/deny/regex")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // List only deny/exact.
    let app3 = helpers::create_pihole_test_app(pool, None).await;
    let response = app3
        .oneshot(
            Request::builder()
                .uri("/domains/deny/exact")
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

    let domains = json["domains"]
        .as_array()
        .expect("domains must be an array");
    for entry in domains {
        assert_eq!(
            entry["kind"], "exact",
            "all entries returned by /domains/deny/exact must have kind == exact"
        );
    }
}

// ---------------------------------------------------------------------------
// PUT /domains/:type/:kind/:domain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_domain_changes_fields() {
    let pool = helpers::create_test_db().await;

    // Create the domain first.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "upd.com" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/deny/exact")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // Update the domain with a comment.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let update_body = serde_json::json!({ "domain": "upd.com", "comment": "updated" }).to_string();
    let response = app2
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/domains/deny/exact/upd.com")
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

    assert_eq!(json["comment"], "updated");
}

// ---------------------------------------------------------------------------
// DELETE /domains/:type/:kind/:domain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_domain_returns_no_content() {
    let pool = helpers::create_test_db().await;

    // Create the domain first.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "del.com" }).to_string();
    let create_response = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains/deny/exact")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // Delete the domain.
    let app2 = helpers::create_pihole_test_app(pool, None).await;
    let response = app2
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/domains/deny/exact/del.com")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_nonexistent_domain_returns_not_found() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/domains/deny/exact/ghost.com")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST /domains:batchDelete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_delete_domains_removes_specified() {
    let pool = helpers::create_test_db().await;

    // Create b1.com.
    let app1 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "b1.com" }).to_string();
    app1.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/deny/exact")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // Create b2.com.
    let app2 = helpers::create_pihole_test_app(pool.clone(), None).await;
    let body = serde_json::json!({ "domain": "b2.com" }).to_string();
    app2.oneshot(
        Request::builder()
            .method("POST")
            .uri("/domains/deny/exact")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("failed to build request"),
    )
    .await
    .expect("request failed");

    // Batch delete both.
    let app3 = helpers::create_pihole_test_app(pool, None).await;
    let delete_body = serde_json::json!({ "items": ["b1.com", "b2.com"] }).to_string();
    let response = app3
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/domains:batchDelete")
                .header("content-type", "application/json")
                .body(Body::from(delete_body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
