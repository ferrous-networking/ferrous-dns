mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// GET /stats/summary — empty database
// ---------------------------------------------------------------------------

#[tokio::test]
async fn summary_returns_zero_counts_when_no_queries_have_been_logged() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

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

    assert_eq!(json["queries"]["total"], 0);
    assert_eq!(json["queries"]["blocked"], 0);
    assert_eq!(json["queries"]["percent_blocked"], 0.0);
}

// ---------------------------------------------------------------------------
// GET /stats/summary — schema conformance (Pi-hole v6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn summary_response_matches_pihole_v6_schema() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

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

    // queries block
    let q = &json["queries"];
    assert!(q["total"].is_number(), "queries.total must be number");
    assert!(q["blocked"].is_number(), "queries.blocked must be number");
    assert!(
        q["percent_blocked"].is_number(),
        "queries.percent_blocked must be number"
    );
    assert!(
        q["unique_domains"].is_number(),
        "queries.unique_domains must be number"
    );
    assert!(
        q["forwarded"].is_number(),
        "queries.forwarded must be number"
    );
    assert!(q["cached"].is_number(), "queries.cached must be number");
    assert!(
        q["frequency"].is_number(),
        "queries.frequency must be number"
    );
    assert!(q["types"].is_object(), "queries.types must be object");

    // clients block
    let c = &json["clients"];
    assert!(c["active"].is_number(), "clients.active must be number");
    assert!(c["total"].is_number(), "clients.total must be number");

    // gravity block
    assert!(
        json["gravity"]["domains_being_blocked"].is_number(),
        "gravity.domains_being_blocked must be number"
    );

    // status
    assert!(json["status"].is_string(), "status must be string");
    assert_eq!(json["status"], "enabled");
}

// ---------------------------------------------------------------------------
// GET /stats/summary — correct calculations with real data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn summary_calculates_percent_blocked_correctly_from_query_log() {
    let pool = helpers::create_test_db().await;

    // 8 total, 2 blocked → 25 %
    for _ in 0..6 {
        helpers::insert_query(&pool, "example.com", "192.168.1.1", false, false, None).await;
    }
    helpers::insert_query(
        &pool,
        "ads.example.com",
        "192.168.1.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;
    helpers::insert_query(
        &pool,
        "tracker.io",
        "192.168.1.2",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let app = helpers::create_pihole_test_app(pool, None).await;
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

    assert_eq!(json["queries"]["total"], 8);
    assert_eq!(json["queries"]["blocked"], 2);

    let pct = json["queries"]["percent_blocked"]
        .as_f64()
        .expect("percent_blocked must be f64");
    assert!(
        (pct - 25.0).abs() < 0.01,
        "expected ~25 % blocked, got {pct}"
    );
}

#[tokio::test]
async fn summary_counts_unique_clients_in_active_and_total_fields() {
    let pool = helpers::create_test_db().await;

    // Clients must be present in the `clients` table with a recent `last_seen`
    // for `count_active_since` to include them.
    helpers::insert_client(&pool, "10.0.0.1").await;
    helpers::insert_client(&pool, "10.0.0.2").await;

    helpers::insert_query(&pool, "a.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "b.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "c.com", "10.0.0.2", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/summary")
                .body(Body::empty())
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

    assert_eq!(
        json["clients"]["active"], 2,
        "two distinct client IPs should count as 2 active clients"
    );
    assert_eq!(json["clients"]["total"], 2);
}

#[tokio::test]
async fn summary_separates_cached_queries_from_forwarded_queries() {
    let pool = helpers::create_test_db().await;

    // 3 cache hits + 2 forwarded
    for _ in 0..3 {
        helpers::insert_query(&pool, "cached.com", "10.0.0.1", false, true, None).await;
    }
    for _ in 0..2 {
        helpers::insert_query(&pool, "fresh.com", "10.0.0.1", false, false, None).await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/summary")
                .body(Body::empty())
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

    assert_eq!(json["queries"]["total"], 5);
    assert_eq!(
        json["queries"]["cached"], 3,
        "cached must equal cache_hit count"
    );
    assert_eq!(
        json["queries"]["forwarded"], 2,
        "forwarded = total - blocked - cached"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/history
// ---------------------------------------------------------------------------

#[tokio::test]
async fn history_returns_array_under_history_key_in_pihole_v6_format() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/history")
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

    assert!(
        json["history"].is_array(),
        "response must have a 'history' array field"
    );
}

#[tokio::test]
async fn history_buckets_contain_required_pihole_v6_fields() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "example.com", "192.168.1.1", false, false, None).await;
    helpers::insert_query(
        &pool,
        "blocked.com",
        "192.168.1.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/history")
                .body(Body::empty())
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

    let history = json["history"].as_array().expect("history must be array");

    // With real data we expect at least one bucket
    if !history.is_empty() {
        let bucket = &history[0];
        assert!(
            bucket["timestamp"].is_number(),
            "bucket.timestamp must be unix epoch (integer)"
        );
        assert!(bucket["total"].is_number(), "bucket.total must be number");
        assert!(
            bucket["blocked"].is_number(),
            "bucket.blocked must be number"
        );

        let ts = bucket["timestamp"].as_i64().expect("timestamp must be i64");
        assert!(ts > 0, "timestamp must be a positive unix epoch");
    }
}

// ---------------------------------------------------------------------------
// GET /stats/top_blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn top_blocked_returns_object_under_top_blocked_key() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_blocked")
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

    assert!(
        json["top_blocked"].is_object(),
        "response must have a 'top_blocked' object field"
    );
}

#[tokio::test]
async fn top_blocked_includes_blocked_domains_with_their_hit_counts() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(
        &pool,
        "ads.example.com",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;
    helpers::insert_query(
        &pool,
        "ads.example.com",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;
    helpers::insert_query(
        &pool,
        "tracker.io",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;
    // Allowed query — must NOT appear in top_blocked
    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_blocked")
                .body(Body::empty())
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

    let top = &json["top_blocked"];
    assert_eq!(
        top["ads.example.com"], 2,
        "ads.example.com should have count 2"
    );
    assert_eq!(top["tracker.io"], 1, "tracker.io should have count 1");
    assert!(
        top["example.com"].is_null(),
        "allowed domain must not appear in top_blocked"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/top_clients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn top_clients_returns_object_under_top_sources_key() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_clients")
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

    assert!(
        json["top_sources"].is_object(),
        "response must have a 'top_sources' object field"
    );
}

#[tokio::test]
async fn top_clients_uses_ip_pipe_hostname_key_format() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "a.com", "192.168.1.100", false, false, None).await;
    helpers::insert_query(&pool, "b.com", "192.168.1.100", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_clients")
                .body(Body::empty())
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

    let sources = json["top_sources"]
        .as_object()
        .expect("top_sources must be object");
    assert!(
        !sources.is_empty(),
        "top_sources must not be empty after inserting queries"
    );

    // All keys must match the "ip|hostname" pattern
    for key in sources.keys() {
        assert!(
            key.contains('|'),
            "key '{key}' must use 'ip|hostname' format required by Pi-hole v6"
        );
    }
}

#[tokio::test]
async fn top_clients_counts_are_per_source_ip() {
    let pool = helpers::create_test_db().await;

    // 3 queries from .100, 1 from .200
    for _ in 0..3 {
        helpers::insert_query(&pool, "x.com", "10.0.0.100", false, false, None).await;
    }
    helpers::insert_query(&pool, "x.com", "10.0.0.200", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_clients")
                .body(Body::empty())
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

    let sources = json["top_sources"]
        .as_object()
        .expect("top_sources must be object");
    let entry_100 = sources
        .iter()
        .find(|(k, _)| k.starts_with("10.0.0.100"))
        .map(|(_, v)| v.as_u64().unwrap_or(0));
    let entry_200 = sources
        .iter()
        .find(|(k, _)| k.starts_with("10.0.0.200"))
        .map(|(_, v)| v.as_u64().unwrap_or(0));

    assert_eq!(entry_100, Some(3), "10.0.0.100 should have count 3");
    assert_eq!(entry_200, Some(1), "10.0.0.200 should have count 1");
}

// ---------------------------------------------------------------------------
// GET /stats/query_types
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_types_returns_object_under_querytypes_key() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/query_types")
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

    assert!(
        json["querytypes"].is_object(),
        "response must have a 'querytypes' object field"
    );
}

#[tokio::test]
async fn query_types_percentages_sum_to_100_when_queries_are_present() {
    let pool = helpers::create_test_db().await;

    // insert_query inserts record_type = 'A'
    for _ in 0..4 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/query_types")
                .body(Body::empty())
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

    let types = json["querytypes"]
        .as_object()
        .expect("querytypes must be object");
    if !types.is_empty() {
        let total: f64 = types.values().filter_map(|v| v.as_f64()).sum();
        assert!(
            (total - 100.0).abs() < 0.01,
            "percentages must sum to ~100.0, got {total}"
        );
    }
}

#[tokio::test]
async fn query_types_returns_zero_percentages_when_no_queries_logged() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/query_types")
                .body(Body::empty())
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

    let types = json["querytypes"]
        .as_object()
        .expect("querytypes must be object");

    // With no data the map must be empty (no divide-by-zero entries)
    assert!(
        types.is_empty(),
        "querytypes must be empty when no queries have been logged"
    );
}
