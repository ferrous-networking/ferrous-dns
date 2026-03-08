mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn history_clients_returns_clients_array() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/history/clients")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["clients"].is_array(), "clients must be an array");
}

#[tokio::test]
async fn history_clients_entries_have_required_fields() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "foo.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "bar.com", "10.0.0.2", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/history/clients")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let clients = json["clients"].as_array().unwrap();
    assert!(
        clients.len() >= 2,
        "expected at least 2 client entries, got {}",
        clients.len()
    );

    for entry in clients {
        assert!(
            entry["name"].is_string(),
            "entry must have 'name' as string"
        );
        assert!(entry["ip"].is_string(), "entry must have 'ip' as string");
        assert!(
            entry["total"].is_number(),
            "entry must have 'total' as number"
        );
    }
}

#[tokio::test]
async fn history_clients_counts_queries_per_client() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "one.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "two.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "three.com", "10.0.0.1", true, false, Some("Exact")).await;
    helpers::insert_query(&pool, "four.com", "10.0.0.2", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/history/clients")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let clients = json["clients"].as_array().unwrap();
    assert!(!clients.is_empty(), "expected client entries");

    let entry = clients
        .iter()
        .find(|e| e["ip"] == "10.0.0.1")
        .expect("10.0.0.1 must be present");
    assert_eq!(entry["total"], 3, "10.0.0.1 should have exactly 3 queries");
}
