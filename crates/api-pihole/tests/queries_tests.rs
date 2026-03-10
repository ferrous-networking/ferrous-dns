mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn get_queries_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(json["queries"].is_array(), "queries must be an array");
    assert!(
        json["recordsTotal"].is_number(),
        "recordsTotal must be a number"
    );
    assert!(
        json["recordsFiltered"].is_number(),
        "recordsFiltered must be a number"
    );
}

#[tokio::test]
async fn get_queries_returns_inserted_queries() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "alpha.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "beta.com", "10.0.0.2", true, false, Some("Exact")).await;
    helpers::insert_query(&pool, "gamma.com", "10.0.0.3", false, true, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let total = json["recordsTotal"].as_u64().unwrap();
    assert_eq!(total, 3, "recordsTotal should be exactly 3, got {total}");

    let queries = json["queries"].as_array().unwrap();
    assert!(!queries.is_empty(), "queries array should not be empty");
}

#[tokio::test]
async fn get_queries_entries_have_required_fields() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let queries = json["queries"].as_array().unwrap();
    assert!(!queries.is_empty(), "expected at least one query entry");

    let entry = &queries[0];
    assert!(entry.get("id").is_some(), "entry must have 'id'");
    assert!(entry.get("time").is_some(), "entry must have 'time'");
    assert!(entry.get("type").is_some(), "entry must have 'type'");
    assert!(entry.get("domain").is_some(), "entry must have 'domain'");
    assert!(entry.get("client").is_some(), "entry must have 'client'");
    assert!(entry.get("status").is_some(), "entry must have 'status'");
    assert!(entry.get("dnssec").is_some(), "entry must have 'dnssec'");
    assert!(entry.get("reply").is_some(), "entry must have 'reply'");
    assert!(
        entry["reply"].is_object(),
        "reply must be an object with 'type' and 'time'"
    );
    assert!(
        entry.get("upstream").is_some(),
        "entry must have 'upstream'"
    );
    assert!(entry.get("cname").is_some(), "entry must have 'cname'");
    assert!(entry.get("list_id").is_some(), "entry must have 'list_id'");
    assert!(entry.get("ede").is_some(), "entry must have 'ede'");
    assert!(
        entry["status"].is_string(),
        "status must be a string (Pi-hole v6 format)"
    );
}

#[tokio::test]
async fn get_queries_with_length_param_limits_results() {
    let pool = helpers::create_test_db().await;

    for i in 0..5 {
        helpers::insert_query(
            &pool,
            &format!("domain{i}.com"),
            "10.0.0.1",
            false,
            false,
            None,
        )
        .await;
    }

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries?length=2")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let queries = json["queries"].as_array().unwrap();
    assert!(
        queries.len() <= 2,
        "expected at most 2 entries, got {}",
        queries.len()
    );
}

#[tokio::test]
async fn suggestions_response_has_all_category_fields_at_root() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries/suggestions")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    // Pi-hole v6 returns categories flat at root level (no wrapper)
    assert!(json["domain"].is_array(), "domain must be an array");
    assert!(json["client_ip"].is_array(), "client_ip must be an array");
    assert!(
        json["client_name"].is_array(),
        "client_name must be an array"
    );
    assert!(json["upstream"].is_array(), "upstream must be an array");
    assert!(json["type"].is_array(), "type must be an array");
    assert!(json["status"].is_array(), "status must be an array");
    assert!(json["reply"].is_array(), "reply must be an array");
    assert!(json["dnssec"].is_array(), "dnssec must be an array");
}

#[tokio::test]
async fn suggestions_includes_queried_domains() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "a.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "b.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries/suggestions")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let domains = json["domain"].as_array().unwrap();
    let domain_strs: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        domain_strs.contains(&"a.com"),
        "suggestions.domain should contain 'a.com'"
    );
    assert!(
        domain_strs.contains(&"b.com"),
        "suggestions.domain should contain 'b.com'"
    );
}

#[tokio::test]
async fn suggestions_are_deduplicated() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "dup.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "dup.com", "10.0.0.2", false, false, None).await;
    helpers::insert_query(&pool, "dup.com", "10.0.0.3", true, false, Some("Exact")).await;

    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries/suggestions")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let domains = json["domain"].as_array().unwrap();
    let dup_count = domains
        .iter()
        .filter(|v| v.as_str() == Some("dup.com"))
        .count();

    assert_eq!(
        dup_count, 1,
        "dup.com should appear exactly once, found {dup_count}"
    );
}

// ---------------------------------------------------------------------------
// GET /api/queries — v6 format validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_status_is_v6_string_not_numeric() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "allowed.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(
        &pool,
        "blocked.com",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;
    helpers::insert_query(&pool, "cached.com", "10.0.0.1", false, true, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let queries = json["queries"].as_array().unwrap();

    let statuses: Vec<&str> = queries
        .iter()
        .filter_map(|q| q["status"].as_str())
        .collect();
    let valid = [
        "GRAVITY",
        "FORWARDED",
        "CACHE",
        "REGEX",
        "DENYLIST",
        "GRAVITY_CNAME",
    ];

    for s in &statuses {
        assert!(
            valid.contains(s),
            "status '{s}' is not a valid Pi-hole v6 status string"
        );
    }
    assert!(
        statuses.contains(&"FORWARDED"),
        "allowed query must map to FORWARDED"
    );
    assert!(
        statuses.contains(&"GRAVITY"),
        "blocked query must map to GRAVITY"
    );
    assert!(
        statuses.contains(&"CACHE"),
        "cached query must map to CACHE"
    );
}

#[tokio::test]
async fn query_reply_is_object_with_type_and_time() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let entry = &json["queries"][0];

    assert!(entry["reply"].is_object(), "reply must be an object");
    assert!(
        entry["reply"]["type"].is_string(),
        "reply.type must be a string"
    );
    assert!(
        entry["reply"]["time"].is_number(),
        "reply.time must be a number"
    );
}

#[tokio::test]
async fn query_client_name_is_null_when_no_hostname() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let entry = &json["queries"][0];

    assert!(
        entry["client"]["name"].is_null(),
        "client.name must be null when hostname is unknown"
    );
}

#[tokio::test]
async fn query_cursor_is_present_as_null_when_not_paginating() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert!(
        json.get("cursor").is_some(),
        "cursor must always be present in response"
    );
}

#[tokio::test]
async fn query_draw_echoed_when_provided() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries?draw=42")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    assert_eq!(json["draw"], 42, "draw must echo the provided value");
}

#[tokio::test]
async fn query_ede_has_default_values() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "example.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let ede = &json["queries"][0]["ede"];

    assert_eq!(ede["code"], -1, "ede.code must default to -1");
    assert!(ede["text"].is_null(), "ede.text must default to null");
}

#[tokio::test]
async fn query_status_filter_accepts_v6_string_gravity() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "allowed.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(
        &pool,
        "blocked.com",
        "10.0.0.1",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries?status=GRAVITY")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");
    let queries = json["queries"].as_array().unwrap();

    for q in queries {
        let status = q["status"].as_str().unwrap();
        assert!(
            ["GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME"].contains(&status),
            "filtering by GRAVITY should only return blocked queries, got '{status}'"
        );
    }
}

// ---------------------------------------------------------------------------
// GET /api/queries/suggestions — category content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suggestions_populates_all_categories() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "test.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(
        &pool,
        "blocked.com",
        "10.0.0.2",
        true,
        false,
        Some("blocklist"),
    )
    .await;

    let app = helpers::create_pihole_test_app(pool, None).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/queries/suggestions")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("json");

    let domains = json["domain"].as_array().unwrap();
    assert!(!domains.is_empty(), "domain suggestions must not be empty");

    let ips = json["client_ip"].as_array().unwrap();
    assert!(!ips.is_empty(), "client_ip suggestions must not be empty");

    let types = json["type"].as_array().unwrap();
    assert!(!types.is_empty(), "type suggestions must not be empty");

    let statuses = json["status"].as_array().unwrap();
    assert!(!statuses.is_empty(), "status suggestions must not be empty");
}
