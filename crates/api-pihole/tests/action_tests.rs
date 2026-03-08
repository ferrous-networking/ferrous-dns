mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// POST /action/gravity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gravity_returns_success() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/action/gravity")
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

    assert_eq!(json["status"], "success", "status must be 'success'");
}

// ---------------------------------------------------------------------------
// POST /action/restartdns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restartdns_returns_success() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/action/restartdns")
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

    assert_eq!(json["status"], "success", "status must be 'success'");
}

// ---------------------------------------------------------------------------
// POST /action/flush/logs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flush_logs_returns_success_on_empty_database() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/action/flush/logs")
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

    assert_eq!(json["status"], "success", "status must be 'success'");
}

#[tokio::test]
async fn flush_logs_clears_query_log_entries() {
    let pool = helpers::create_test_db().await;

    // Insert 3 queries and backdate them so the flush (delete_older_than 0 days)
    // cutoff is strictly after their created_at timestamps.
    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    sqlx::query("UPDATE query_log SET created_at = datetime('now', '-1 day')")
        .execute(&pool)
        .await
        .expect("failed to backdate query log entries");

    let app = helpers::create_pihole_test_app(pool.clone(), None).await;

    // Flush logs
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/action/flush/logs")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    // Verify via GET /stats/summary that total is now 0
    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/summary")
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

    assert_eq!(
        json["queries"]["total"], 0,
        "total queries must be 0 after flushing logs"
    );
}
