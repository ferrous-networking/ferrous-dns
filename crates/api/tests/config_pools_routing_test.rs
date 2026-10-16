//! `POST /config` with conditional pools: the routing fields round-trip,
//! apply live, and every rule the resolver relies on is checked before
//! anything is applied.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_infrastructure::dns::load_balancer::{Route, UpstreamRouter};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

/// Groups "Office A" and "Office B" get ids 2 and 3.
const OFFICE_A: i64 = 2;

async fn test_app() -> TestApp {
    let config_path = std::env::temp_dir()
        .join(format!(
            "ferrous_cfg_routing_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, "").unwrap();
    TestApp::builder()
        .config_path(&config_path)
        .groups(&["Office A", "Office B"])
        .build()
        .await
}

async fn send(app: Router, method: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri("/config")
        .header("content-type", "application/json");
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let response = app.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn default_pool() -> Value {
    json!({ "name": "public", "strategy": "parallel", "priority": 1,
            "servers": ["udp://9.9.9.9:53"] })
}

fn office_pool() -> Value {
    json!({ "name": "office-a", "strategy": "failover", "priority": 1,
            "servers": ["udp://10.0.0.10:53"],
            "domains": ["corp.example", "рф"], "groups": [OFFICE_A], "internal": true })
}

async fn post_pools(app: Router, pools: Value) -> (StatusCode, Value) {
    send(app, "POST", Some(json!({ "dns": { "pools": pools } }))).await
}

async fn assert_rejected(pools: Value, expected: &str) {
    let app = test_app().await;
    let (status, json) = post_pools(app.router.clone(), pools).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["success"], false);
    let error = json["error"].as_str().unwrap();
    assert!(
        error.contains(expected),
        "expected {expected:?} in {error:?}"
    );
    // Nothing was applied: the live set still has no conditional pool.
    assert_eq!(
        app.pool_manager.route("x.corp.example", Some(OFFICE_A)),
        None
    );
    assert_eq!(
        app.config
            .read()
            .await
            .dns
            .pools
            .iter()
            .filter(|p| p.is_conditional())
            .count(),
        0
    );
}

#[tokio::test]
async fn test_conditional_pool_round_trips_and_applies_live() {
    let app = test_app().await;

    let (status, json) =
        post_pools(app.router.clone(), json!([default_pool(), office_pool()])).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["success"], true);
    assert_eq!(json["restart_required"], false, "pools are hot-applied");

    let (_, config) = send(app.router.clone(), "GET", None).await;
    let pools = config["dns"]["pools"].as_array().unwrap();
    let office = pools.iter().find(|p| p["name"] == "office-a").unwrap();
    assert_eq!(office["domains"], json!(["corp.example", "рф"]));
    assert_eq!(office["groups"], json!([OFFICE_A]));
    assert_eq!(office["internal"], true);
    let public = pools.iter().find(|p| p["name"] == "public").unwrap();
    assert_eq!(public["domains"], json!([]));
    assert_eq!(public["groups"], json!([]));
    assert_eq!(public["internal"], false);

    assert_eq!(
        app.pool_manager.route("host.corp.example", Some(OFFICE_A)),
        Some(Route {
            view: OFFICE_A as u32,
            internal: true
        })
    );
    assert!(app
        .pool_manager
        .route("пример.рф", Some(OFFICE_A))
        .is_none());
    assert!(app
        .pool_manager
        .route("xn--e1afmkfd.xn--p1ai", Some(OFFICE_A))
        .is_some());
}

#[tokio::test]
async fn test_pool_without_routing_fields_still_saves() {
    let app = test_app().await;
    let (status, json) = post_pools(app.router.clone(), json!([default_pool()])).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["success"], true);
}

#[tokio::test]
async fn test_rejects_groups_without_domains() {
    let mut pool = default_pool();
    pool["groups"] = json!([OFFICE_A]);
    assert_rejected(json!([pool]), "sets groups without domains").await;
}

#[tokio::test]
async fn test_rejects_internal_without_domains() {
    let mut pool = default_pool();
    pool["internal"] = json!(true);
    assert_rejected(json!([pool]), "is internal without domains").await;
}

#[tokio::test]
async fn test_rejects_conditional_pools_only() {
    assert_rejected(
        json!([office_pool()]),
        "At least one pool must have no domains",
    )
    .await;
}

#[tokio::test]
async fn test_rejects_an_invalid_domain() {
    let mut office = office_pool();
    office["domains"] = json!(["*.corp.example"]);
    assert_rejected(
        json!([default_pool(), office]),
        "Pool 'office-a': domain '*.corp.example'",
    )
    .await;
}

#[tokio::test]
async fn test_rejects_a_domain_routed_twice_for_the_same_clients() {
    let mut other = office_pool();
    other["name"] = json!("office-a-backup");
    other["domains"] = json!(["Corp.Example."]);
    assert_rejected(
        json!([default_pool(), office_pool(), other]),
        "is routed to both pool",
    )
    .await;
}

#[tokio::test]
async fn test_rejects_a_group_that_does_not_exist() {
    let mut office = office_pool();
    office["groups"] = json!([99]);
    assert_rejected(
        json!([default_pool(), office]),
        "client group 99, which does not exist",
    )
    .await;
}

async fn delete_group(app: Router, id: i64) -> (StatusCode, String) {
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/groups/{id}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn test_deleting_a_group_a_pool_routes_for_is_refused() {
    let app = test_app().await;
    let (status, json) =
        post_pools(app.router.clone(), json!([default_pool(), office_pool()])).await;
    assert_eq!(status, StatusCode::OK, "{json}");

    let (status, body) = delete_group(app.router.clone(), OFFICE_A).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("office-a"), "{body}");

    // The group survives, so the pool that routes for it still saves.
    let (status, json) =
        post_pools(app.router.clone(), json!([default_pool(), office_pool()])).await;
    assert_eq!(status, StatusCode::OK, "{json}");
}

#[tokio::test]
async fn test_blank_domains_are_dropped() {
    let app = test_app().await;
    let mut office = office_pool();
    office["domains"] = json!(["corp.example", "  ", ""]);
    let (status, json) = post_pools(app.router.clone(), json!([default_pool(), office])).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let config = app.config.read().await;
    let office = config
        .dns
        .pools
        .iter()
        .find(|p| p.name == "office-a")
        .unwrap();
    assert_eq!(office.domains, ["corp.example"]);
}
