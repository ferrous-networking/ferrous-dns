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

    assert!(
        !history.is_empty(),
        "expected at least one bucket after inserting queries"
    );
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
        json["domains"].is_array(),
        "response must have a 'domains' array field"
    );
    assert!(
        json["total_queries"].is_number(),
        "response must have 'total_queries'"
    );
    assert!(
        json["blocked_queries"].is_number(),
        "response must have 'blocked_queries'"
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

    let domains = json["domains"].as_array().expect("domains must be array");
    let ads_entry = domains.iter().find(|d| d["domain"] == "ads.example.com");
    assert_eq!(
        ads_entry.unwrap()["count"],
        2,
        "ads.example.com should have count 2"
    );
    let tracker_entry = domains.iter().find(|d| d["domain"] == "tracker.io");
    assert_eq!(
        tracker_entry.unwrap()["count"],
        1,
        "tracker.io should have count 1"
    );
    assert!(
        domains.iter().all(|d| d["domain"] != "example.com"),
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
        json["clients"].is_array(),
        "response must have a 'clients' array field"
    );
    assert!(
        json["total_queries"].is_number(),
        "response must have 'total_queries'"
    );
    assert!(
        json["blocked_queries"].is_number(),
        "response must have 'blocked_queries'"
    );
}

#[tokio::test]
async fn top_clients_entries_have_ip_and_count_fields() {
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

    let clients = json["clients"].as_array().expect("clients must be array");
    assert!(
        !clients.is_empty(),
        "clients must not be empty after inserting queries"
    );

    let entry = &clients[0];
    assert!(
        entry["ip"].is_string(),
        "client entry must have 'ip' string"
    );
    assert!(
        entry["name"].is_string(),
        "client entry must have 'name' string (empty string when unknown)"
    );
    assert!(
        entry["count"].is_number(),
        "client entry must have 'count' number"
    );
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

    let clients = json["clients"].as_array().expect("clients must be array");
    let entry_100 = clients
        .iter()
        .find(|c| c["ip"] == "10.0.0.100")
        .map(|c| c["count"].as_u64().unwrap_or(0));
    let entry_200 = clients
        .iter()
        .find(|c| c["ip"] == "10.0.0.200")
        .map(|c| c["count"].as_u64().unwrap_or(0));

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
    assert!(
        !types.is_empty(),
        "querytypes must not be empty when queries have been inserted"
    );
    let total: f64 = types.values().filter_map(|v| v.as_f64()).sum();
    assert!(
        (total - 100.0).abs() < 0.01,
        "percentages must sum to ~100.0, got {total}"
    );
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

// ---------------------------------------------------------------------------
// GET /stats/top_domains
// ---------------------------------------------------------------------------

#[tokio::test]
async fn top_domains_returns_both_top_domains_and_top_blocked_keys() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_domains")
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
        json["domains"].is_array(),
        "response must have a 'domains' array field"
    );
    assert!(
        json["total_queries"].is_number(),
        "response must have 'total_queries'"
    );
    assert!(
        json["blocked_queries"].is_number(),
        "response must have 'blocked_queries'"
    );
}

#[tokio::test]
async fn top_domains_returns_allowed_domains_by_default() {
    let pool = helpers::create_test_db().await;

    // 3 allowed queries for "example.com"
    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    // 2 blocked queries for "ads.com"
    for _ in 0..2 {
        helpers::insert_query(&pool, "ads.com", "10.0.0.1", true, false, Some("blocklist")).await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_domains")
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

    let domains = json["domains"].as_array().expect("domains must be array");

    let example_entry = domains.iter().find(|d| d["domain"] == "example.com");
    assert!(
        example_entry.is_some(),
        "example.com should appear in allowed top_domains"
    );
    assert_eq!(
        example_entry.unwrap()["count"],
        3,
        "example.com should have count 3"
    );

    assert!(
        domains.iter().all(|d| d["domain"] != "ads.com"),
        "blocked domain must not appear in default (allowed) top_domains"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/upstreams
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upstreams_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/upstreams")
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
        json["upstreams"].is_object(),
        "response must have an 'upstreams' object field"
    );
    assert!(
        json["forwarded_queries"].is_number(),
        "response must have a 'forwarded_queries' number field"
    );
    assert!(
        json["total_queries"].is_number(),
        "response must have a 'total_queries' number field"
    );
}

#[tokio::test]
async fn upstreams_total_queries_matches_data() {
    let pool = helpers::create_test_db().await;

    for _ in 0..5 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/upstreams")
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
        json["total_queries"], 5,
        "total_queries must equal the number of inserted queries"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/recent_blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recent_blocked_returns_domain_field() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/recent_blocked")
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
        json.get("domain").is_some(),
        "response must have a 'domain' key"
    );
}

#[tokio::test]
async fn recent_blocked_returns_most_recently_blocked_domain() {
    let pool = helpers::create_test_db().await;

    // 2 allowed queries
    helpers::insert_query(&pool, "good.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "safe.org", "10.0.0.1", false, false, None).await;

    // 1 blocked query
    helpers::insert_query(
        &pool,
        "ads.evil.com",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/recent_blocked")
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
        json["domain"], "ads.evil.com",
        "most recently blocked domain must be ads.evil.com"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/top_domains?blocked=true — v6 blocked filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn top_domains_blocked_true_returns_only_blocked_domains() {
    let pool = helpers::create_test_db().await;

    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    for _ in 0..2 {
        helpers::insert_query(&pool, "ads.com", "10.0.0.1", true, false, Some("blocklist")).await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/stats/top_domains?blocked=true")
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

    let domains = json["domains"].as_array().expect("domains must be array");

    let ads_entry = domains.iter().find(|d| d["domain"] == "ads.com");
    assert!(
        ads_entry.is_some(),
        "ads.com should appear when ?blocked=true"
    );
    assert_eq!(ads_entry.unwrap()["count"], 2);

    assert!(
        domains.iter().all(|d| d["domain"] != "example.com"),
        "allowed domain must not appear when ?blocked=true"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/history — cached and forwarded fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn history_buckets_include_cached_and_forwarded_fields() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

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
    assert!(!history.is_empty(), "expected at least one bucket");

    let bucket = &history[0];
    assert!(
        bucket["cached"].is_number(),
        "bucket.cached must be a number"
    );
    assert!(
        bucket["forwarded"].is_number(),
        "bucket.forwarded must be a number"
    );
}

// ---------------------------------------------------------------------------
// GET /stats/summary — gravity.last_update present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn summary_gravity_includes_last_update_field() {
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

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    assert!(
        json["gravity"]["last_update"].is_number(),
        "gravity.last_update must be a number"
    );
}
