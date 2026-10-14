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
    let app = helpers::create_pihole_test_app(pool).await;

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

    assert_eq!(json["blocking"], "enabled");
}

#[tokio::test]
async fn get_blocking_response_has_timer_field() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

async fn post_blocking(app: &axum::Router, body: &'static str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("json")
}

async fn get_status(app: &axum::Router) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dns/blocking")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("json")
}

async fn blocking_enabled(app: &axum::Router) -> bool {
    match get_status(app).await["blocking"].as_str() {
        Some("enabled") => true,
        Some("disabled") => false,
        other => panic!("blocking must be enabled or disabled, got {other:?}"),
    }
}

#[tokio::test]
async fn disabling_blocking_is_applied_to_the_engine() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    post_blocking(&app, r#"{"blocking":false}"#).await;

    assert!(!blocking_enabled(&app).await);
}

#[tokio::test]
async fn enabling_blocking_after_a_disable_is_applied_to_the_engine() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    post_blocking(&app, r#"{"blocking":false}"#).await;
    post_blocking(&app, r#"{"blocking":true}"#).await;

    assert!(blocking_enabled(&app).await);
}

#[tokio::test]
async fn disable_with_timer_re_enables_blocking_when_it_expires() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    let reply = post_blocking(&app, r#"{"blocking":false,"timer":60}"#).await;
    assert_eq!(reply["timer"].as_f64(), Some(60.0));
    // Let the spawned timer task arm its sleep before the clock moves.
    tokio::task::yield_now().await;

    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    assert!(
        !blocking_enabled(&app).await,
        "still disabled before expiry"
    );

    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(blocking_enabled(&app).await, "re-enabled after expiry");
    assert!(get_status(&app).await["timer"].is_null());
}

#[tokio::test]
async fn get_reports_the_seconds_left_on_a_pending_timer() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    post_blocking(&app, r#"{"blocking":false,"timer":60}"#).await;
    let status = get_status(&app).await;
    assert_eq!(status["blocking"], "disabled");
    let left = status["timer"].as_f64().expect("timer must be a number");
    assert!(
        left > 0.0 && left <= 60.0,
        "timer {left} must be within (0, 60]"
    );

    tokio::time::advance(std::time::Duration::from_secs(20)).await;
    assert_eq!(get_status(&app).await["timer"].as_f64(), Some(40.0));
}

#[tokio::test]
async fn enable_with_timer_disables_blocking_when_it_expires() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    post_blocking(&app, r#"{"blocking":false}"#).await;
    let reply = post_blocking(&app, r#"{"blocking":true,"timer":5}"#).await;
    assert_eq!(reply["timer"].as_f64(), Some(5.0));
    assert!(
        blocking_enabled(&app).await,
        "enabled until the timer fires"
    );

    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(!blocking_enabled(&app).await, "flipped back after expiry");
}

#[tokio::test]
async fn a_new_request_cancels_the_pending_timer() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    tokio::time::pause();

    post_blocking(&app, r#"{"blocking":false,"timer":60}"#).await;
    tokio::task::yield_now().await;
    let reply = post_blocking(&app, r#"{"blocking":false}"#).await;
    assert!(reply["timer"].is_null());
    assert!(get_status(&app).await["timer"].is_null());

    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(!blocking_enabled(&app).await);
}

#[tokio::test]
async fn an_unrepresentable_timer_is_rejected() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/blocking")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"blocking":false,"timer":{}}}"#,
                    u64::MAX
                )))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        blocking_enabled(&app).await,
        "a rejected request changes nothing"
    );
}
