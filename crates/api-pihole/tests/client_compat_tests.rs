//! The requests real Pi-hole v6 clients send, replayed against the router.
//!
//! - Homarr (`homarr-labs/homarr`, `packages/integrations/src/pi-hole`) probes
//!   `GET /info/login` to tell v6 from v5, and posts JSON through undici
//!   `fetch` without a Content-Type, which undici sends as `text/plain`.
//! - Home Assistant (`python-hole` 0.9.2, `hole/v6.py`) reads `/info/version`
//!   as a nested object and disables blocking with `timer: true` or a float.
//! - eko/pihole-exporter decodes `/stats/upstreams` and `/stats/top_*` into
//!   typed Go structs and sends `count` / `blocked` query parameters.

mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::auth::APP_PASSWORD;
use helpers::ftl::{self, assert_ftl_shape};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// What undici puts on a `fetch` whose body is a string.
const UNDICI_STRING_BODY: &str = "text/plain;charset=UTF-8";

/// Status and body; a body that is not JSON comes back as a JSON string.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build request")
}

fn post(uri: &str, content_type: Option<&str>, body: impl Into<Body>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    builder.body(body.into()).expect("failed to build request")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    post(uri, Some("application/json"), body.to_string())
}

/// `[auth]` disabled, so routes answer without a session.
async fn open_app() -> (sqlx::SqlitePool, Router) {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool.clone()).await;
    (pool, app)
}

/// `[auth]` enabled; [`APP_PASSWORD`] is a valid API token.
async fn auth_app() -> Router {
    let pool = helpers::create_test_db().await;
    helpers::create_pihole_test_app_with_auth(pool, false).await
}

#[tokio::test]
async fn info_login_is_served_without_a_session() {
    let app = auth_app().await;

    let (status, body) = send(&app, get("/info/login")).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Homarr reads a 404 here as Pi-hole v5: {body}"
    );
    assert_ftl_shape::<ftl::InfoLogin>(&body);
}

#[tokio::test]
async fn login_accepts_a_json_body_sent_as_text_plain() {
    let app = auth_app().await;
    let body = json!({ "password": APP_PASSWORD }).to_string();

    let (status, reply) = send(&app, post("/auth", Some(UNDICI_STRING_BODY), body)).await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["session"]["valid"], true);
    assert!(reply["session"]["sid"].is_string());
}

#[tokio::test]
async fn login_accepts_a_json_body_with_no_content_type() {
    let app = auth_app().await;
    let body = json!({ "password": APP_PASSWORD }).to_string();

    let (status, reply) = send(&app, post("/auth", None, body)).await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["session"]["valid"], true);
}

#[tokio::test]
async fn blocking_toggle_accepts_a_json_body_sent_as_text_plain() {
    let (_, app) = open_app().await;

    let (status, reply) = send(
        &app,
        post(
            "/dns/blocking",
            Some(UNDICI_STRING_BODY),
            r#"{"blocking":false}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
}

#[tokio::test]
async fn domain_create_accepts_a_json_body_sent_as_text_plain() {
    let (_, app) = open_app().await;

    let (status, reply) = send(
        &app,
        post(
            "/domains/deny/exact",
            Some(UNDICI_STRING_BODY),
            r#"{"domain":"ads.example.com"}"#,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{reply}");
}

#[tokio::test]
async fn blocking_status_is_reported_as_enabled_or_disabled() {
    let (_, app) = open_app().await;

    let (_, enabled) = send(&app, get("/dns/blocking")).await;
    assert_ftl_shape::<ftl::DnsBlocking>(&enabled);
    assert_eq!(enabled["blocking"], "enabled");

    let (_, reply) = send(
        &app,
        post_json("/dns/blocking", json!({ "blocking": false })),
    )
    .await;
    assert_ftl_shape::<ftl::DnsBlocking>(&reply);
    assert_eq!(reply["blocking"], "disabled");

    let (_, disabled) = send(&app, get("/dns/blocking")).await;
    assert_eq!(disabled["blocking"], "disabled");
}

#[tokio::test]
async fn blocking_disable_with_a_non_numeric_timer_sets_no_timer() {
    let (_, app) = open_app().await;

    let (status, reply) = send(
        &app,
        post_json("/dns/blocking", json!({ "blocking": false, "timer": true })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["blocking"], "disabled");
    assert!(reply["timer"].is_null(), "{reply}");
}

#[tokio::test]
async fn blocking_disable_with_a_float_timer_starts_the_timer() {
    let (_, app) = open_app().await;

    let (status, reply) = send(
        &app,
        post_json(
            "/dns/blocking",
            json!({ "blocking": false, "timer": 300.0 }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let left = reply["timer"].as_f64().expect("timer must be a number");
    assert!((299.0..=300.0).contains(&left), "timer {left}");
}

#[tokio::test]
async fn info_version_is_the_nested_component_object() {
    let (_, app) = open_app().await;

    let (status, body) = send(&app, get("/info/version")).await;

    assert_eq!(status, StatusCode::OK);
    let version = assert_ftl_shape::<ftl::InfoVersion>(&body);
    assert_eq!(
        body["version"]["ftl"]["local"]["version"],
        format!("v{}", env!("CARGO_PKG_VERSION")),
        "{version:?}"
    );
}

#[tokio::test]
async fn upstreams_are_an_array_of_servers() {
    let (pool, app) = open_app().await;
    helpers::insert_upstream_query(&pool, "a.test", "default", "udp://1.1.1.1:53").await;

    let (status, body) = send(&app, get("/stats/upstreams")).await;

    assert_eq!(status, StatusCode::OK);
    assert_ftl_shape::<ftl::StatsUpstreams>(&body);
    let upstreams = body["upstreams"].as_array().expect("upstreams array");
    let server = upstreams
        .iter()
        .find(|u| u["ip"] == "1.1.1.1")
        .unwrap_or_else(|| panic!("no 1.1.1.1 entry: {body}"));
    assert_eq!(server["port"], 53);
    assert_eq!(server["count"], 1);
}

#[tokio::test]
async fn top_domains_returns_at_most_count_entries() {
    let (pool, app) = open_app().await;
    for n in 0..12 {
        helpers::insert_query(&pool, &format!("d{n}.test"), "10.0.0.1", false, false, None).await;
    }

    let (_, three) = send(&app, get("/stats/top_domains?count=3")).await;
    let (_, default) = send(&app, get("/stats/top_domains")).await;

    assert_ftl_shape::<ftl::StatsTopDomains>(&three);
    assert_eq!(
        three["domains"].as_array().map(Vec::len),
        Some(3),
        "{three}"
    );
    assert_eq!(
        default["domains"].as_array().map(Vec::len),
        Some(10),
        "{default}"
    );
}

#[tokio::test]
async fn top_clients_with_blocked_true_counts_blocked_queries_only() {
    let (pool, app) = open_app().await;
    for _ in 0..3 {
        helpers::insert_query(&pool, "ok.test", "10.0.0.1", false, false, None).await;
    }
    for _ in 0..2 {
        helpers::insert_query(
            &pool,
            "ads.test",
            "10.0.0.5",
            true,
            false,
            Some("blocklist"),
        )
        .await;
    }

    let (_, body) = send(&app, get("/stats/top_clients?blocked=true")).await;

    assert_ftl_shape::<ftl::StatsTopClients>(&body);
    let clients = body["clients"].as_array().expect("clients array");
    assert_eq!(clients.len(), 1, "{body}");
    assert_eq!(clients[0]["ip"], "10.0.0.5");
    assert_eq!(clients[0]["count"], 2);
}

#[tokio::test]
async fn summary_matches_the_ftl_schema() {
    let (pool, app) = open_app().await;
    helpers::insert_query(&pool, "ok.test", "10.0.0.1", false, false, None).await;
    helpers::insert_query(
        &pool,
        "ads.test",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let (status, body) = send(&app, get("/stats/summary")).await;

    assert_eq!(status, StatusCode::OK);
    assert_ftl_shape::<ftl::StatsSummary>(&body);
}

#[tokio::test]
async fn invalid_bodies_get_a_pihole_error_envelope() {
    let (_, app) = open_app().await;

    for body in ["{}", "not json"] {
        let (status, reply) =
            send(&app, post("/dns/blocking", Some("application/json"), body)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {reply}");
        assert_ftl_shape::<ftl::ErrorReply>(&reply);
        assert_eq!(reply["error"]["key"], "bad_request", "{body}");
    }
}
