mod helpers;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use helpers::ftl::{self, assert_ftl_shape};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

/// pihole's COL_TABLE `TICK`, as gravity prints it when FTL passes `FORCE_COLOR`.
const COLORED_TICK: &str = "[\x1b[32m✓\x1b[0m]";

async fn post(app: Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().expect("ascii content-type").to_string());
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    (status, content_type, bytes.to_vec())
}

async fn post_gravity(uri: &str) -> String {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, content_type, body) = post(app, uri).await;

    assert_eq!(status, StatusCode::OK);
    let content_type = content_type.expect("gravity must send a Content-Type");
    assert!(
        content_type.starts_with("text/plain"),
        "gravity streams pihole -g output as text/plain, got {content_type}"
    );
    String::from_utf8(body).expect("gravity output must be UTF-8")
}

#[tokio::test]
async fn gravity_streams_plain_text_progress_like_pihole_g() {
    let output = post_gravity("/action/gravity").await;

    assert!(
        output.contains("  [i] "),
        "progress lines carry pihole's [i] marker:\n{output}"
    );
    assert!(
        output.contains("[✓]"),
        "a finished step is ticked:\n{output}"
    );
    assert!(
        output.contains("Number of gravity domains: 0"),
        "the compiled domain count is reported:\n{output}"
    );
    assert!(
        !output.contains('\x1b'),
        "no ANSI escapes unless ?color=true:\n{output}"
    );
}

#[tokio::test]
async fn gravity_with_color_uses_pihole_ansi_markers() {
    let output = post_gravity("/action/gravity?color=true").await;

    assert!(
        output.contains(COLORED_TICK),
        "?color=true colors the tick as pihole's COL_TABLE does:\n{output:?}"
    );
}

#[tokio::test]
async fn gravity_with_color_false_stays_plain() {
    let output = post_gravity("/action/gravity?color=false").await;

    assert!(!output.contains('\x1b'), "{output:?}");
}

#[tokio::test]
async fn restartdns_replies_ftl_success_body() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, _, body) = post(app, "/action/restartdns").await;

    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).expect("invalid JSON");
    assert_ftl_shape::<ftl::ActionSuccess>(&json);
}

#[tokio::test]
async fn flush_logs_replies_ftl_success_body() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, _, body) = post(app, "/action/flush/logs").await;

    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).expect("invalid JSON");
    assert_ftl_shape::<ftl::ActionSuccess>(&json);
}

async fn count_rows(pool: &sqlx::SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("failed to count rows")
}

#[tokio::test]
async fn flush_logs_clears_query_log_entries() {
    let pool = helpers::create_test_db().await;

    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    // FTL deletes every stored query up to the flush, not only the last 24
    // hours (log.c flush_dnsmasq_log → delete_old_queries_from_db(false, now),
    // `DELETE FROM query_storage WHERE timestamp <= ?`). One row is older than
    // a day; the others are backdated so the second-precision cutoff is
    // strictly after them.
    sqlx::query("UPDATE query_log SET created_at = datetime('now', '-1 minute')")
        .execute(&pool)
        .await
        .expect("failed to backdate query log entries");
    sqlx::query(
        "UPDATE query_log SET created_at = datetime('now', '-3 days') \
         WHERE id = (SELECT MIN(id) FROM query_log)",
    )
    .execute(&pool)
    .await
    .expect("failed to backdate the oldest entry");
    assert_eq!(count_rows(&pool, "query_log").await, 3);
    assert!(count_rows(&pool, "query_log_minute").await > 0);

    let app = helpers::create_pihole_test_app(pool.clone()).await;
    let (status, _, _) = post(app, "/action/flush/logs").await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(count_rows(&pool, "query_log").await, 0);
    assert_eq!(
        count_rows(&pool, "query_log_minute").await,
        0,
        "the minute rollups behind /stats and /history are flushed too"
    );

    let app = helpers::create_pihole_test_app(pool).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/summary")
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

    assert_eq!(
        json["queries"]["total"], 0,
        "total queries must be 0 after flushing logs"
    );
}
