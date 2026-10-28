//! Every paged list answers one envelope, `{data, total, limit, offset}`, plus
//! `records_total` and `next_cursor` where the endpoint has them, and echoes
//! the `limit` it applied.
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_application::ports::ClientRepository;
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::IpAddr;
use tower::ServiceExt;

mod helpers;

async fn get_json(app: Router, uri: &str) -> Value {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn assert_envelope(json: &Value, extra: &[&str]) {
    let mut expected: Vec<&str> = ["data", "total", "limit", "offset"]
        .iter()
        .chain(extra)
        .copied()
        .collect();
    expected.sort_unstable();
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap_or_else(|| panic!("not an envelope: {json}"))
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, expected, "{json}");
    assert!(json["data"].is_array(), "{json}");
}

/// Ten clients seen a minute apart, newest first: 192.168.1.1 … .10.
async fn seed_clients(app: &TestApp) {
    for i in 1..=10 {
        let ip: IpAddr = format!("192.168.1.{i}").parse().unwrap();
        app.client_repo.update_last_seen(ip).await.unwrap();
    }
    app.client_repo.flush_writes().await;
    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-' || \
         CAST(substr(ip_address, 11) AS INTEGER) || ' minutes')",
    )
    .execute(&app.pool)
    .await
    .unwrap();
}

fn ips(json: &Value) -> Vec<&str> {
    json["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["ip_address"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn test_clients_answer_the_envelope_with_a_total() {
    let app = TestApp::new().await;
    seed_clients(&app).await;

    let json = get_json(app.router.clone(), "/clients?limit=4&offset=2").await;

    assert_envelope(&json, &[]);
    assert_eq!(json["total"], 10);
    assert_eq!(json["limit"], 4);
    assert_eq!(json["offset"], 2);
    assert_eq!(
        ips(&json),
        ["192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"]
    );
}

#[tokio::test]
async fn test_clients_page_with_active_days_honours_the_offset() {
    let app = TestApp::new().await;
    seed_clients(&app).await;
    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-40 days') \
         WHERE ip_address IN ('192.168.1.9', '192.168.1.10')",
    )
    .execute(&app.pool)
    .await
    .unwrap();

    let json = get_json(
        app.router.clone(),
        "/clients?active_days=30&limit=5&offset=5",
    )
    .await;

    assert_envelope(&json, &[]);
    assert_eq!(json["total"], 8);
    assert_eq!(json["offset"], 5);
    assert_eq!(ips(&json), ["192.168.1.6", "192.168.1.7", "192.168.1.8"]);
}

#[tokio::test]
async fn test_clients_echo_the_clamped_limit() {
    let app = TestApp::new().await.router;

    let json = get_json(app, "/clients?limit=5000").await;

    assert_envelope(&json, &[]);
    assert_eq!(json["limit"], 1000);
}

#[tokio::test]
async fn test_managed_domains_echo_the_clamped_limit() {
    let app = TestApp::new().await.router;

    let json = get_json(app, "/managed-domains?limit=5000").await;

    assert_envelope(&json, &[]);
    assert_eq!(json["limit"], 1000);
}

#[tokio::test]
async fn test_cache_entries_answer_the_envelope_with_records_total() {
    let app = TestApp::new().await.router;

    let json = get_json(app, "/cache/entries?limit=5000").await;

    assert_envelope(&json, &["records_total"]);
    assert_eq!(json["limit"], 500);
}

#[tokio::test]
async fn test_queries_answer_the_envelope_and_echo_the_clamped_limit() {
    let app = TestApp::new().await.router;

    let json = get_json(app, "/queries?limit=5000").await;

    assert_envelope(&json, &["records_total", "next_cursor"]);
    assert_eq!(json["limit"], 1000);
}

#[tokio::test]
async fn test_queries_paged_by_cursor_echo_offset_zero() {
    let app = TestApp::new().await.router;

    let json = get_json(app, "/queries?cursor=1&offset=7").await;

    assert_eq!(json["offset"], 0, "{json}");
}
