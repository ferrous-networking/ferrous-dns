use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use ferrous_dns_api::create_api_router_with_openapi;
use ferrous_dns_application::use_cases::GetAuthStatusUseCase;
use ferrous_dns_domain::Config;
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

mod helpers;

/// The API router with `[auth] enabled = true`; no session or API token is sent.
async fn app_with_auth_enabled() -> Router {
    let TestApp { mut state, .. } = TestApp::new().await;
    let mut config = Config::default();
    config.auth.enabled = true;
    state.auth.get_auth_status = Arc::new(GetAuthStatusUseCase::new(Arc::new(RwLock::new(config))));
    create_api_router_with_openapi(state).0
}

async fn get(app: Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_string());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, content_type, body.to_vec())
}

#[tokio::test]
async fn test_health_needs_no_credentials_with_auth_enabled() {
    let app = app_with_auth_enabled().await;

    // Guard: auth really is on, so a protected route refuses the same request.
    let (status, _, _) = get(app.clone(), "/stats").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, body) = get(app, "/health").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
}

#[tokio::test]
async fn test_health_answers_json_with_the_status_and_version() {
    let app = TestApp::new().await.router;

    let (status, content_type, body) = get(app, "/health").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") })
    );
}
