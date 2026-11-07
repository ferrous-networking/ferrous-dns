//! What the server is serving reaches `GET /metrics` from `AppState`, read at
//! scrape time: the DNS listener flag `/health` uses.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_api::metrics_routes;
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
async fn the_dns_listener_gauge_follows_the_health_flag() {
    let app = TestApp::new().await;
    assert!(scrape(&app)
        .await
        .contains("\nferrousdns_dns_listening 1\n"));

    app.state.dns_listening.store(false, Ordering::Relaxed);

    assert!(scrape(&app)
        .await
        .contains("\nferrousdns_dns_listening 0\n"));
}
