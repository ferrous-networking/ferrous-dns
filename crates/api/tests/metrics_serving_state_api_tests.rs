//! What the server is serving reaches `GET /metrics` from `AppState`, read at
//! scrape time: the DNS listener flag `/health` uses, and the certificates the
//! TLS listeners loaded.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_api::metrics_routes;
use ferrous_dns_application::tls_certificates::TlsListener;
use helpers::TestApp;
use http_body_util::BodyExt;
use std::sync::atomic::Ordering;
use tower::ServiceExt;

mod helpers;

async fn scrape(app: &TestApp) -> String {
    let response = metrics_routes(app.state.clone())
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn test_the_dns_listener_gauge_follows_the_health_flag() {
    let app = TestApp::new().await;
    assert!(scrape(&app)
        .await
        .contains("\nferrousdns_dns_listening 1\n"));

    app.state.dns_listening.store(false, Ordering::Relaxed);

    assert!(scrape(&app)
        .await
        .contains("\nferrousdns_dns_listening 0\n"));
}

#[tokio::test]
async fn test_a_loaded_certificate_is_scraped_under_its_listener() {
    let app = TestApp::new().await;
    assert!(!scrape(&app)
        .await
        .contains("ferrousdns_tls_cert_not_after_seconds{"));

    app.state
        .loaded_certificates
        .record(TlsListener::Doq, 1_900_000_000);

    assert!(scrape(&app)
        .await
        .contains("ferrousdns_tls_cert_not_after_seconds{listener=\"doq\"} 1900000000"));
}
