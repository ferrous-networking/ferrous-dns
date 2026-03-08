mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn get_blocking_returns_status() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["blocking"].is_boolean());
    assert!(json["blocking"].as_bool().unwrap());
}

#[tokio::test]
async fn get_blocking_response_has_timer_field() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(
        json.get("timer").is_some(),
        "response must contain a 'timer' field"
    );
}

#[tokio::test]
async fn set_blocking_disable_returns_success() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"blocking":false}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(!json["blocking"].as_bool().unwrap());
}

#[tokio::test]
async fn set_blocking_enable_returns_success() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"blocking":true}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["blocking"].as_bool().unwrap());
}

#[tokio::test]
async fn set_blocking_with_timer_returns_success() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"blocking":false,"timer":60}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(!json["blocking"].as_bool().unwrap());
    assert_eq!(json["timer"].as_u64().unwrap(), 60);
}
