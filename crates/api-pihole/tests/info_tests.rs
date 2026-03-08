mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /info/version
// ---------------------------------------------------------------------------

#[tokio::test]
async fn version_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/version")
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

    assert!(json["version"].is_string(), "version must be a string");
    assert!(json["branch"].is_string(), "branch must be a string");
    assert!(json["hash"].is_string(), "hash must be a string");
}

#[tokio::test]
async fn version_contains_valid_semver() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/version")
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

    let version = json["version"].as_str().expect("version must be a string");
    assert!(
        version.contains('.'),
        "version '{version}' must contain a dot (basic semver check)"
    );
}

// ---------------------------------------------------------------------------
// GET /info/ftl
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ftl_info_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/ftl")
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

    assert!(json["pid"].is_number(), "pid must be a number");
    assert!(json["uptime"].is_number(), "uptime must be a number");

    let db = &json["database"];
    assert!(db.is_object(), "database must be an object");
    assert!(
        db["gravity"].is_number(),
        "database.gravity must be a number"
    );
    assert!(
        db["queries"].is_number(),
        "database.queries must be a number"
    );
}

// ---------------------------------------------------------------------------
// GET /info/system
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_info_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/system")
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

    let load = json["load"].as_array().expect("load must be an array");
    assert_eq!(load.len(), 3, "load must contain exactly 3 elements");
    for (i, item) in load.iter().enumerate() {
        assert!(item.is_number(), "load[{i}] must be a number");
    }

    let memory = &json["memory"];
    assert!(memory["total"].is_number(), "memory.total must be a number");
    assert!(memory["used"].is_number(), "memory.used must be a number");
    assert!(
        memory["percent"].is_number(),
        "memory.percent must be a number"
    );

    let disk = &json["disk"];
    assert!(disk["total"].is_number(), "disk.total must be a number");
    assert!(disk["used"].is_number(), "disk.used must be a number");
    assert!(disk["percent"].is_number(), "disk.percent must be a number");
}

// ---------------------------------------------------------------------------
// GET /info/host
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_info_returns_hostname_string() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/host")
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

    let hostname = json["hostname"]
        .as_str()
        .expect("hostname must be a string");
    assert!(!hostname.is_empty(), "hostname must be a non-empty string");
}

// ---------------------------------------------------------------------------
// GET /info/database
// ---------------------------------------------------------------------------

#[tokio::test]
async fn database_info_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/database")
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

    assert!(json["queries"].is_number(), "queries must be a number");
    assert!(json["filesize"].is_number(), "filesize must be a number");
}
