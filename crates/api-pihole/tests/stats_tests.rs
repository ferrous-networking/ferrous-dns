mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn summary_returns_zero_counts_when_no_queries_have_been_logged() {
    let pool = helpers::create_test_db().await;
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

    assert_eq!(json["queries"]["total"], 0);
    assert_eq!(json["queries"]["blocked"], 0);
    assert_eq!(json["queries"]["percent_blocked"], 0.0);
}

#[tokio::test]
async fn summary_response_matches_pihole_v6_schema() {
    let pool = helpers::create_test_db().await;
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

    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsSummary>(&json);
}

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
        "cache hits are not forwarded"
    );
}

#[tokio::test]
async fn summary_does_not_count_local_dns_answers_as_forwarded() {
    let pool = helpers::create_test_db().await;
    helpers::insert_upstream_query(&pool, "remote.example", "default", "1.1.1.1:53").await;
    for _ in 0..2 {
        helpers::insert_local_dns_query(&pool, "nas.lan").await;
    }

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/stats/summary").await;

    assert_eq!(json["queries"]["total"], 3);
    assert_eq!(json["queries"]["forwarded"], 1);
}

#[tokio::test]
async fn history_returns_array_under_history_key_in_pihole_v6_format() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn top_blocked_returns_object_under_top_blocked_key() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn top_clients_returns_object_under_top_sources_key() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn query_types_counts_queries_under_ftl_type_keys() {
    let pool = helpers::create_test_db().await;
    // insert_query logs record_type 'A'
    for _ in 0..4 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/stats/query_types").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsQueryTypes>(&json);
    assert_eq!(json["types"]["A"], 4);
    assert_eq!(json["types"]["AAAA"], 0);
    assert_eq!(json["types"]["OTHER"], 0);
}

#[tokio::test]
async fn query_types_lists_every_type_key_when_no_queries_logged() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/stats/query_types").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsQueryTypes>(&json);
    assert!(json["types"]
        .as_object()
        .expect("types object")
        .values()
        .all(|count| count == 0));
}

#[tokio::test]
async fn top_domains_returns_both_top_domains_and_top_blocked_keys() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn upstreams_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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
        json["upstreams"].is_array(),
        "response must have an 'upstreams' array field"
    );
    assert!(
        json["forwarded_queries"].is_number(),
        "response must have a 'forwarded_queries' number field"
    );
    assert!(
        json["total_queries"].is_number(),
        "response must have a 'total_queries' number field"
    );
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsUpstreams>(&json);
}

#[tokio::test]
async fn upstreams_total_queries_matches_data() {
    let pool = helpers::create_test_db().await;

    for _ in 0..5 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }

    let app = helpers::create_pihole_test_app(pool).await;
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

async fn get_json(app: axum::Router, uri: &str) -> Value {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("invalid JSON")
}

#[tokio::test]
async fn upstreams_list_blocklist_and_cache_then_each_server() {
    let pool = helpers::create_test_db().await;
    for _ in 0..3 {
        helpers::insert_upstream_query(&pool, "a.example", "default", "1.1.1.1:53").await;
    }
    helpers::insert_upstream_query(&pool, "b.example", "default", "[2606:4700::1111]:53").await;
    helpers::insert_query(&pool, "c.example", "10.0.0.1", false, true, None).await;
    for source in [
        "blocklist",
        "regex_filter",
        "dns_tunneling",
        "managed_domain",
    ] {
        helpers::insert_query(&pool, "ads.example", "10.0.0.1", true, false, Some(source)).await;
    }

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/stats/upstreams").await;

    let entries: Vec<(Value, Value, Value)> = json["upstreams"]
        .as_array()
        .expect("upstreams array")
        .iter()
        .map(|u| (u["ip"].clone(), u["port"].clone(), u["count"].clone()))
        .collect();
    assert_eq!(
        entries,
        vec![
            ("blocklist".into(), (-1).into(), 4.into()),
            ("cache".into(), (-1).into(), 1.into()),
            ("1.1.1.1".into(), 53.into(), 3.into()),
            ("2606:4700::1111".into(), 53.into(), 1.into()),
        ]
    );
    assert_eq!(json["forwarded_queries"], 4);
    assert_eq!(json["total_queries"], 9);
}

#[tokio::test]
async fn out_of_range_period_is_clamped_instead_of_overflowing() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    let app = helpers::create_pihole_test_app(pool).await;

    for from in ["1e30", "-1e30", "inf", "NaN"] {
        let summary = get_json(app.clone(), &format!("/stats/summary?from={from}")).await;
        assert!(summary["queries"]["total"].is_u64(), "from={from}");
        get_json(app.clone(), &format!("/stats/top_domains?from={from}")).await;
        get_json(app.clone(), &format!("/stats/top_clients?from={from}")).await;
    }
}

#[tokio::test]
async fn recent_blocked_returns_an_empty_list_when_nothing_was_blocked() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "good.com", "10.0.0.1", false, false, None).await;
    let app = helpers::create_pihole_test_app(pool).await;

    let json = get_json(app, "/stats/recent_blocked").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsRecentBlocked>(&json);
    assert_eq!(json["blocked"], serde_json::json!([]));
}

#[tokio::test]
async fn recent_blocked_lists_count_blocked_domains_newest_first() {
    let pool = helpers::create_test_db().await;
    for domain in ["first.ads", "second.ads", "third.ads"] {
        helpers::insert_query(&pool, domain, "10.0.0.1", true, false, Some("blocklist")).await;
        helpers::insert_query(&pool, "good.com", "10.0.0.1", false, false, None).await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    // FTL's default count is 1.
    let json = get_json(app.clone(), "/stats/recent_blocked").await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsRecentBlocked>(&json);
    assert_eq!(json["blocked"], serde_json::json!(["third.ads"]));

    let json = get_json(app, "/stats/recent_blocked?count=2").await;
    assert_eq!(
        json["blocked"],
        serde_json::json!(["third.ads", "second.ads"])
    );
}

#[tokio::test]
async fn top_domains_blocked_true_returns_only_blocked_domains() {
    let pool = helpers::create_test_db().await;

    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    for _ in 0..2 {
        helpers::insert_query(&pool, "ads.com", "10.0.0.1", true, false, Some("blocklist")).await;
    }

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn history_buckets_include_cached_and_forwarded_fields() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool).await;
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

#[tokio::test]
async fn summary_gravity_includes_last_update_field() {
    let pool = helpers::create_test_db().await;
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

#[tokio::test]
async fn summary_gravity_last_update_is_the_newest_list_download() {
    // FTL reports when gravity last ran; Ferrous stamps each list when it is
    // downloaded, so the newest stamp is the last run that fetched anything.
    let pool = helpers::create_test_db().await;
    for (table, name, synced) in [
        ("blocklist_sources", "older", "2026-10-01 10:00:00"),
        ("whitelist_sources", "newer", "2026-10-02 08:30:00"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO {table} (name, url, last_synced_at) VALUES (?, ?, ?)"
        ))
        .bind(name)
        .bind(format!("https://lists.example/{name}.txt"))
        .bind(synced)
        .execute(&pool)
        .await
        .expect("failed to insert list");
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = helpers::send(app, "GET", "/stats/summary").await;

    assert_eq!(status, StatusCode::OK);
    let newest = chrono::NaiveDateTime::parse_from_str("2026-10-02 08:30:00", "%Y-%m-%d %H:%M:%S")
        .expect("valid timestamp")
        .and_utc()
        .timestamp();
    assert_eq!(json["gravity"]["last_update"], newest);
}

#[tokio::test]
async fn summary_unique_domains_counts_distinct_client_domains() {
    let pool = helpers::create_test_db().await;
    for (domain, blocked) in [
        ("a.example", false),
        ("a.example", false),
        ("b.example", false),
        ("ads.example", true),
    ] {
        helpers::insert_query(&pool, domain, "10.0.0.1", blocked, false, None).await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = helpers::send(app, "GET", "/stats/summary").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["queries"]["unique_domains"], 3);
}

#[tokio::test]
async fn query_frequency_is_the_rate_of_the_last_minute() {
    // FTL averages queries per second over its last 30 s; Ferrous counts the
    // last minute.
    let pool = helpers::create_test_db().await;
    for _ in 0..6 {
        helpers::insert_query(&pool, "a.example", "10.0.0.1", false, false, None).await;
    }
    let expected = 6.0 / 60.0;

    for (uri, pointer) in [
        ("/stats/summary", "/queries/frequency"),
        ("/info/ftl", "/ftl/query_frequency"),
        ("/padd", "/queries/query_frequency"),
    ] {
        let app = helpers::create_pihole_test_app(pool.clone()).await;
        let (status, json) = helpers::send(app, "GET", uri).await;

        assert_eq!(status, StatusCode::OK, "{uri}");
        let frequency = json.pointer(pointer).and_then(Value::as_f64);
        assert_eq!(frequency, Some(expected), "{uri} {pointer}");
    }
}

#[tokio::test]
async fn summary_total_clients_counts_every_known_client() {
    // As /info/ftl does: every client in the table, not only the active ones.
    let pool = helpers::create_test_db().await;
    helpers::insert_client(&pool, "10.0.0.1").await;
    helpers::insert_query(&pool, "a.com", "10.0.0.1", false, false, None).await;
    sqlx::query(
        "INSERT INTO clients (ip_address, last_seen) VALUES ('10.0.0.9', '2026-01-01 00:00:00')",
    )
    .execute(&pool)
    .await
    .expect("failed to insert client");
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = helpers::send(app, "GET", "/stats/summary").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["clients"]["active"], 1);
    assert_eq!(json["clients"]["total"], 2);
}

#[tokio::test]
async fn history_matches_ftl_with_cached_and_forwarded_split() {
    let pool = helpers::create_test_db().await;
    for _ in 0..2 {
        helpers::insert_query(&pool, "cached.com", "10.0.0.1", false, true, None).await;
    }
    helpers::insert_local_dns_query(&pool, "nas.lan").await;
    helpers::insert_upstream_query(&pool, "remote.example", "default", "1.1.1.1:53").await;
    helpers::insert_query(&pool, "ads.com", "10.0.0.1", true, false, Some("blocklist")).await;

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/history").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::History>(&json);
    let history = json["history"].as_array().expect("history array");
    assert_eq!(history.len(), 145, "Glance expects 145 buckets");
    let bucket = history
        .iter()
        .find(|b| b["total"] != 0)
        .expect("a bucket with the queries");
    // FTL counts local records as cached; forwarded is upstream answers only.
    assert_eq!(bucket["total"], 5);
    assert_eq!(bucket["cached"], 3);
    assert_eq!(bucket["blocked"], 1);
    assert_eq!(bucket["forwarded"], 1);
}

#[tokio::test]
async fn history_timestamps_are_bucket_centres() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/stats/history").await;

    // overTime.c centres each 10-minute slot: start + 300.
    for bucket in json["history"].as_array().expect("history array") {
        let ts = bucket["timestamp"].as_i64().expect("integer timestamp");
        assert_eq!(ts % 600, 300, "timestamp {ts} is not a bucket centre");
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// `from`/`until` covering the last hour, as Unix timestamps.
fn last_hour() -> String {
    let now = unix_now();
    format!("from={}&until={}", now - 3_600, now + 60)
}

const DATABASE_ROUTES: [&str; 5] = [
    "/stats/database/summary",
    "/stats/database/top_domains",
    "/stats/database/top_clients",
    "/stats/database/upstreams",
    "/stats/database/query_types",
];

#[tokio::test]
async fn database_stats_require_from_and_until() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;
    let now = unix_now();

    for route in DATABASE_ROUTES {
        for query in [
            String::new(),
            format!("?from={now}"),
            format!("?until={now}"),
        ] {
            let uri = format!("{route}{query}");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .body(Body::empty())
                        .expect("failed to build request"),
                )
                .await
                .expect("request failed");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("failed to read body")
                .to_bytes();
            let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");
            helpers::ftl::assert_ftl_shape::<helpers::ftl::ErrorReply>(&json);
            assert_eq!(json["error"]["key"], "bad_request", "{uri}");
            assert_eq!(
                json["error"]["message"],
                "You need to specify both \"from\" and \"until\" in the request.",
                "{uri}"
            );
        }
    }
}

#[tokio::test]
async fn database_summary_matches_ftl() {
    let pool = helpers::create_test_db().await;
    helpers::insert_client(&pool, "10.0.0.1").await;
    helpers::insert_client(&pool, "10.0.0.2").await;
    for _ in 0..3 {
        helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;
    }
    helpers::insert_query(&pool, "ads.com", "10.0.0.2", true, false, Some("blocklist")).await;

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, &format!("/stats/database/summary?{}", last_hour())).await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsDatabaseSummary>(&json);
    assert_eq!(json["sum_queries"], 4);
    assert_eq!(json["sum_blocked"], 1);
    assert_eq!(json["percent_blocked"], 25.0);
    assert_eq!(json["total_clients"], 2);
}

#[tokio::test]
async fn database_top_lists_match_ftl() {
    let pool = helpers::create_test_db().await;
    for _ in 0..2 {
        helpers::insert_upstream_query(&pool, "remote.example", "default", "1.1.1.1:53").await;
    }
    helpers::insert_query(&pool, "ads.com", "10.0.0.2", true, false, Some("blocklist")).await;
    let app = helpers::create_pihole_test_app(pool).await;
    let window = last_hour();

    let json = get_json(
        app.clone(),
        &format!("/stats/database/top_domains?{window}"),
    )
    .await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsDatabaseTopDomains>(&json);
    assert_eq!(json["domains"][0]["domain"], "remote.example");
    assert_eq!(json["domains"][0]["count"], 2);

    let json = get_json(
        app.clone(),
        &format!("/stats/database/top_domains?{window}&blocked=true"),
    )
    .await;
    assert_eq!(json["domains"][0]["domain"], "ads.com");

    let json = get_json(
        app.clone(),
        &format!("/stats/database/top_clients?{window}"),
    )
    .await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsDatabaseTopClients>(&json);
    assert_eq!(json["clients"][0]["ip"], "10.0.0.1");
    assert_eq!(json["clients"][0]["count"], 2);
    // A client without a stored name is null in FTL's long-term top list.
    assert!(json["clients"][0]["name"].is_null(), "{json}");

    let json = get_json(app.clone(), &format!("/stats/database/upstreams?{window}")).await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsDatabaseUpstreams>(&json);
    assert_eq!(json["forwarded_queries"], 2);
    assert_eq!(json["total_queries"], 3);

    let json = get_json(app, &format!("/stats/database/query_types?{window}")).await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::StatsDatabaseQueryTypes>(&json);
    assert_eq!(json["types"]["A"], 3);
}
