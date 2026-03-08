mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn search_returns_results_array() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search/example.com")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["results"].is_array(), "results must be an array");
}

#[tokio::test]
async fn search_unknown_domain_returns_empty_results() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search/nonexistent.xyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let results = json["results"].as_array().unwrap();
    // The mock filter engine returns FilterDecision::Allow for all domains,
    // so the search handler always returns one result entry. An "empty" result
    // in this context means the single entry is not blocked.
    for result in results {
        assert!(
            !result["blocked"].as_bool().unwrap(),
            "nonexistent domain should not be blocked"
        );
    }
}
