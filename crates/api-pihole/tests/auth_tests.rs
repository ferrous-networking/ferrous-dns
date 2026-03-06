mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_auth_returns_unauthenticated_session_when_no_active_session() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, Some("secret-key")).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let body = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("invalid JSON");

    assert!(
        json["session"].is_object(),
        "response must have a 'session' field"
    );
    assert_eq!(json["session"]["valid"], false);
    assert_eq!(json["session"]["totp"], false);
    assert!(
        json["session"]["sid"]
            .as_str()
            .unwrap_or("nonempty")
            .is_empty(),
        "sid must be empty for unauthenticated session"
    );
    assert!(
        json["session"]["validity"].as_i64().unwrap_or(1) == 0,
        "validity must be 0 for unauthenticated session"
    );
}

// ---------------------------------------------------------------------------
// POST /auth — successful login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_api_key_returns_valid_session() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, Some("my-api-key")).await;

    let body = serde_json::json!({ "password": "my-api-key" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
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

    assert_eq!(
        json["session"]["valid"], true,
        "session.valid must be true on success"
    );
    assert_eq!(json["session"]["totp"], false);
    assert_eq!(
        json["session"]["sid"], "my-api-key",
        "sid should echo the provided password"
    );
    assert!(
        json["session"]["validity"].as_i64().unwrap_or(0) > 0,
        "validity must be positive on success"
    );
}

#[tokio::test]
async fn login_with_any_password_succeeds_when_no_api_key_is_configured() {
    let pool = helpers::create_test_db().await;
    // None = no API key configured → open access
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "password": "anything-at-all" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
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

    assert_eq!(
        json["session"]["valid"], true,
        "any password should be accepted when no API key is configured"
    );
}

// ---------------------------------------------------------------------------
// POST /auth — failed login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_wrong_api_key_returns_unauthorized_and_invalid_session() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, Some("correct-key")).await;

    let body = serde_json::json!({ "password": "wrong-key" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert_eq!(
        json["session"]["valid"], false,
        "session.valid must be false on failed login"
    );
    assert!(
        json["session"]["sid"]
            .as_str()
            .unwrap_or("nonempty")
            .is_empty(),
        "sid must be empty on failed login"
    );
    assert_eq!(
        json["session"]["validity"], 0,
        "validity must be 0 on failed login"
    );
}

#[tokio::test]
async fn login_with_empty_password_returns_unauthorized_when_api_key_is_configured() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, Some("non-empty-key")).await;

    let body = serde_json::json!({ "password": "" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// DELETE /auth — logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_returns_no_content() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, Some("key")).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// Pi-hole v6 schema conformance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_response_schema_contains_all_required_pihole_v6_session_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let body = serde_json::json!({ "password": "any" }).to_string();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth")
                .header("content-type", "application/json")
                .body(Body::from(body))
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

    let session = &json["session"];
    assert!(
        session["valid"].is_boolean(),
        "session.valid must be boolean"
    );
    assert!(session["totp"].is_boolean(), "session.totp must be boolean");
    assert!(session["sid"].is_string(), "session.sid must be string");
    assert!(session["csrf"].is_string(), "session.csrf must be string");
    assert!(
        session["validity"].is_number(),
        "session.validity must be number"
    );
    assert!(
        session["message"].is_string(),
        "session.message must be string"
    );
}
