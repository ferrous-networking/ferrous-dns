use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::{create_test_db, TestApp};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

mod helpers;

/// Stats read the minute rollups; rebuild them from the raw fixture rows with
/// the production backfill.
async fn rebuild_rollups(pool: &sqlx::SqlitePool) {
    sqlx::raw_sql(concat!(
        "DELETE FROM query_log_minute; DELETE FROM query_log_minute_record_type;",
        "DELETE FROM query_log_minute_block_source; DELETE FROM query_log_minute_upstream;",
        include_str!("../../../migrations/20260923000002_backfill_query_log_rollups.sql"),
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_query_log(
    pool: &sqlx::SqlitePool,
    cache_hit: bool,
    blocked: bool,
    block_source: Option<&str>,
) {
    let (up_server, up_pool): (Option<&str>, Option<&str>) = if !cache_hit && !blocked {
        (Some("dns.google"), Some("pool1"))
    } else {
        (None, None)
    };
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source, upstream_server, upstream_pool)
         VALUES ('example.com', 'A', '192.168.1.1', ?, 100, ?, 'client', ?, ?, ?)",
    )
    .bind(if blocked { 1i64 } else { 0i64 })
    .bind(if cache_hit { 1i64 } else { 0i64 })
    .bind(block_source)
    .bind(up_server)
    .bind(up_pool)
    .execute(pool)
    .await
    .unwrap();
    rebuild_rollups(pool).await;
}

#[tokio::test]
async fn test_get_stats_empty() {
    let pool = create_test_db().await;
    let app = TestApp::builder().pool(pool).build().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["queries_total"], 0);
    assert_eq!(json["queries_blocked"], 0);
}

#[tokio::test]
async fn test_get_stats_has_source_stats_field() {
    let pool = create_test_db().await;
    let app = TestApp::builder().pool(pool).build().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let ss = &json["source_stats"];
    assert!(ss.is_object(), "source_stats must be an object");
    assert!(ss["cache"].is_number());
    assert!(ss["local_dns"].is_number());
}

#[tokio::test]
async fn test_get_stats_with_data() {
    let pool = create_test_db().await;

    // 2 cache hits + 3 upstream
    insert_query_log(&pool, true, false, None).await;
    insert_query_log(&pool, true, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    insert_query_log(&pool, false, false, None).await;
    // 1 blocklist block
    insert_query_log(&pool, false, true, Some("blocklist")).await;

    let app = TestApp::builder().pool(pool).build().await.router;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["queries_total"], 6);
    assert_eq!(json["queries_blocked"], 1);

    let ss = &json["source_stats"];
    assert_eq!(ss["cache"], 2);
    assert_eq!(ss["pool1:dns.google"], 3);
    assert_eq!(ss["blocklist"], 1);
    assert_eq!(ss["managed_domain"], serde_json::Value::Null);
    assert_eq!(ss["regex_filter"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_get_stats_period_parameter() {
    let pool = create_test_db().await;

    // Insert 1 recent query
    insert_query_log(&pool, false, false, None).await;
    // Insert 1 old query (far in the past)
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, created_at)
         VALUES ('old.example.com', 'A', '10.0.0.1', 0, 50, 0, 'client', '2000-01-01 00:00:00')",
    )
    .execute(&pool)
    .await
    .unwrap();
    rebuild_rollups(&pool).await;

    let app = TestApp::builder().pool(pool).build().await.router;

    // 1h period: only the recent query
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats?period=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["queries_total"], 1);
}

#[tokio::test]
async fn test_dashboard_includes_top_blocked_and_clients() {
    let pool = create_test_db().await;

    insert_query_log(&pool, false, true, Some("blocklist")).await;
    insert_query_log(&pool, false, false, None).await;

    let app = TestApp::builder().pool(pool).build().await.router;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dashboard?period=24h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["top_blocked_domains"].is_array());
    assert!(json["top_clients"].is_array());
    assert_eq!(json["top_blocked_domains"].as_array().unwrap().len(), 1);
    assert_eq!(json["top_blocked_domains"][0]["domain"], "example.com");
    assert_eq!(json["top_blocked_domains"][0]["count"], 1);
    assert!(!json["top_clients"].as_array().unwrap().is_empty());
}

/// The dashboard reports the master switch the process runs with, not the
/// saved config, which only applies after a restart.
#[tokio::test]
async fn test_dashboard_reports_whether_malware_detection_runs() {
    for running in [true, false] {
        let TestApp {
            mut state, config, ..
        } = TestApp::builder().build().await;
        state.malware_detection_enabled = running;
        // A save that has not been applied yet.
        config.write().await.dns.malware_detection_enabled = !running;
        let app = ferrous_dns_api::create_api_router_with_openapi(state).0;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard?period=24h")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["malware_detection_enabled"], running);
    }
}

#[tokio::test]
async fn test_timeline_reports_the_granularity_it_used() {
    let app = TestApp::builder().build().await.router;

    for (requested, effective) in [
        ("minute", "minute"),
        ("quarter_hour", "15min"),
        ("day", "day"),
        // An unknown value falls back to hourly buckets; the response must say so.
        ("fortnight", "hour"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/queries/timeline?period=24h&granularity={requested}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["granularity"], effective, "requested {requested}");
    }
}
