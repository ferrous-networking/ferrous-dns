mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_domain::config::BlockResponseMode;
use helpers::ftl::{self, assert_ftl_shape};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn get_queries_returns_required_fields() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;

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
async fn suggestions_response_wraps_every_category() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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

    // FTL wraps the categories in `suggestions` (queries.c api_queries_suggestions).
    let suggestions = &json["suggestions"];
    for category in [
        "domain",
        "client_ip",
        "client_name",
        "upstream",
        "type",
        "status",
        "reply",
        "dnssec",
    ] {
        assert!(
            suggestions[category].is_array(),
            "{category} must be an array"
        );
    }
}

#[tokio::test]
async fn suggestions_includes_queried_domains() {
    let pool = helpers::create_test_db().await;

    helpers::insert_query(&pool, "a.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "b.com", "10.0.0.1", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool).await;

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

    let domains = json["suggestions"]["domain"].as_array().unwrap();
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

    let app = helpers::create_pihole_test_app(pool).await;

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

    let domains = json["suggestions"]["domain"].as_array().unwrap();
    let dup_count = domains
        .iter()
        .filter(|v| v.as_str() == Some("dup.com"))
        .count();

    assert_eq!(
        dup_count, 1,
        "dup.com should appear exactly once, found {dup_count}"
    );
}

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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let app = helpers::create_pihole_test_app(pool).await;
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
async fn query_cursor_is_present_when_not_paginating() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

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
    let app = helpers::create_pihole_test_app(pool).await;

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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let app = helpers::create_pihole_test_app(pool).await;
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

    let suggestions = &json["suggestions"];
    let domains = suggestions["domain"].as_array().unwrap();
    assert!(!domains.is_empty(), "domain suggestions must not be empty");

    let ips = suggestions["client_ip"].as_array().unwrap();
    assert!(!ips.is_empty(), "client_ip suggestions must not be empty");

    let types = suggestions["type"].as_array().unwrap();
    assert!(!types.is_empty(), "type suggestions must not be empty");

    let statuses = suggestions["status"].as_array().unwrap();
    assert!(!statuses.is_empty(), "status suggestions must not be empty");
}

// ---------------------------------------------------------------------------
// FTL conformance (queries.c api_queries / api_queries_suggestions)
// ---------------------------------------------------------------------------

/// One `query_log` row; unset columns keep the table defaults.
#[derive(Default)]
struct Row<'a> {
    domain: &'a str,
    record_type: Option<&'a str>,
    client_ip: Option<&'a str>,
    blocked: bool,
    cache_hit: bool,
    block_source: Option<&'a str>,
    response_status: Option<&'a str>,
    answers: Option<&'a str>,
    upstream_server: Option<&'a str>,
    dnssec_status: Option<&'a str>,
    response_time_us: Option<i64>,
    /// SQLite modifier for `datetime('now', ?)`, e.g. `-2 hours`.
    age: Option<&'a str>,
}

async fn insert_row(pool: &sqlx::SqlitePool, row: Row<'_>) -> i64 {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, cache_hit, block_source,
                                response_status, answers, upstream_server, dnssec_status,
                                response_time_ms, query_source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'client', datetime('now', ?))",
    )
    .bind(row.domain)
    .bind(row.record_type.unwrap_or("A"))
    .bind(row.client_ip.unwrap_or("10.0.0.1"))
    .bind(i64::from(row.blocked))
    .bind(i64::from(row.cache_hit))
    .bind(row.block_source)
    .bind(row.response_status)
    .bind(row.answers)
    .bind(row.upstream_server)
    .bind(row.dnssec_status)
    .bind(row.response_time_us)
    .bind(row.age.unwrap_or("+0 seconds"))
    .execute(pool)
    .await
    .expect("Failed to insert query log row")
    .last_insert_rowid()
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, serde_json::from_slice(&body).expect("json"))
}

/// The entry for `domain` in a `/queries` reply.
fn entry<'a>(json: &'a Value, domain: &str) -> &'a Value {
    json["queries"]
        .as_array()
        .expect("queries array")
        .iter()
        .find(|q| q["domain"] == domain)
        .unwrap_or_else(|| panic!("{domain} missing from {json}"))
}

fn ids(json: &Value) -> Vec<i64> {
    json["queries"]
        .as_array()
        .expect("queries array")
        .iter()
        .map(|q| q["id"].as_i64().expect("id"))
        .collect()
}

#[tokio::test]
async fn queries_reply_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "answered.com",
            response_status: Some("NOERROR"),
            answers: Some("1.2.3.4"),
            upstream_server: Some("udp://1.1.1.1:53"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "validated.com",
            response_status: Some("NOERROR"),
            dnssec_status: Some("Indeterminate"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "blocked.com",
            blocked: true,
            block_source: Some("blocklist"),
            response_status: Some("BLOCKED"),
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = get(&app, "/queries").await;

    assert_eq!(status, StatusCode::OK);
    let reply = assert_ftl_shape::<ftl::Queries>(&json);
    assert_eq!(reply.draw, 0, "draw defaults to 0");
    assert_eq!(reply.queries.len(), 3);
}

#[tokio::test]
async fn reply_time_is_in_seconds() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "slow.com",
            response_status: Some("NOERROR"),
            response_time_us: Some(250_000),
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    assert_eq!(entry(&json, "slow.com")["reply"]["time"], 0.25);
}

#[tokio::test]
async fn reply_type_names_the_kind_of_answer() {
    let pool = helpers::create_test_db().await;
    let rows = [
        (
            Row {
                domain: "ip.com",
                response_status: Some("NOERROR"),
                answers: Some("1.2.3.4"),
                ..Default::default()
            },
            "IP",
        ),
        (
            Row {
                domain: "nodata.com",
                response_status: Some("NOERROR"),
                ..Default::default()
            },
            "NODATA",
        ),
        (
            Row {
                domain: "nx.com",
                response_status: Some("NXDOMAIN"),
                ..Default::default()
            },
            "NXDOMAIN",
        ),
        (
            Row {
                domain: "fail.com",
                response_status: Some("SERVFAIL"),
                ..Default::default()
            },
            "SERVFAIL",
        ),
        (
            Row {
                domain: "slow.com",
                response_status: Some("TIMEOUT"),
                ..Default::default()
            },
            "NONE",
        ),
        (
            Row {
                domain: "cached.com",
                cache_hit: true,
                response_status: Some("NOERROR"),
                answers: Some("5.6.7.8"),
                ..Default::default()
            },
            "IP",
        ),
        (
            Row {
                domain: "nas.lan",
                response_status: Some("LOCAL_DNS"),
                answers: Some("192.168.1.5"),
                ..Default::default()
            },
            "IP",
        ),
        (
            Row {
                domain: "ads.com",
                blocked: true,
                block_source: Some("blocklist"),
                response_status: Some("BLOCKED"),
                ..Default::default()
            },
            "IP",
        ),
        (
            Row {
                domain: "ads-txt.com",
                record_type: Some("TXT"),
                blocked: true,
                block_source: Some("blocklist"),
                response_status: Some("BLOCKED"),
                ..Default::default()
            },
            "NODATA",
        ),
        (
            Row {
                domain: "flood.com",
                blocked: true,
                block_source: Some("rate_limit"),
                response_status: Some("RATE_LIMITED"),
                ..Default::default()
            },
            "REFUSED",
        ),
    ];
    let expected: Vec<(String, &str)> = rows
        .iter()
        .map(|(r, t)| (r.domain.to_string(), *t))
        .collect();
    for (row, _) in rows {
        insert_row(&pool, row).await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    for (domain, reply) in expected {
        assert_eq!(
            entry(&json, &domain)["reply"]["type"],
            reply,
            "reply.type of {domain}"
        );
    }
}

#[tokio::test]
async fn blocked_reply_type_follows_the_configured_block_mode() {
    for (mode, reply) in [
        (BlockResponseMode::NxDomain, "NXDOMAIN"),
        (BlockResponseMode::NoData, "NODATA"),
        (BlockResponseMode::Refused, "REFUSED"),
    ] {
        let pool = helpers::create_test_db().await;
        insert_row(
            &pool,
            Row {
                domain: "ads.com",
                blocked: true,
                block_source: Some("blocklist"),
                response_status: Some("BLOCKED"),
                ..Default::default()
            },
        )
        .await;
        let app =
            helpers::create_pihole_test_app_with_config(pool, |c| c.blocking.block_mode = mode)
                .await;

        let (_, json) = get(&app, "/queries").await;

        assert_eq!(
            entry(&json, "ads.com")["reply"]["type"],
            reply,
            "block_mode {mode:?}"
        );
    }
}

#[tokio::test]
async fn dnssec_uses_ftl_names() {
    let pool = helpers::create_test_db().await;
    for (domain, status) in [
        ("secure.com", Some("Secure")),
        ("insecure.com", Some("Insecure")),
        ("bogus.com", Some("Bogus")),
        ("indeterminate.com", Some("Indeterminate")),
        ("unvalidated.com", None),
    ] {
        insert_row(
            &pool,
            Row {
                domain,
                response_status: Some("NOERROR"),
                dnssec_status: status,
                ..Default::default()
            },
        )
        .await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    for (domain, dnssec) in [
        ("secure.com", "SECURE"),
        ("insecure.com", "INSECURE"),
        ("bogus.com", "BOGUS"),
        ("indeterminate.com", "ABANDONED"),
        ("unvalidated.com", "UNKNOWN"),
    ] {
        assert_eq!(entry(&json, domain)["dnssec"], dnssec, "dnssec of {domain}");
    }
}

#[tokio::test]
async fn upstream_is_ip_hash_port_or_null() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "v4.com",
            upstream_server: Some("udp://1.1.1.1:53"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "v6.com",
            upstream_server: Some("tls://[2606:4700:4700::1111]:853"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "cached.com",
            cache_hit: true,
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    assert_eq!(entry(&json, "v4.com")["upstream"], "1.1.1.1#53");
    assert_eq!(
        entry(&json, "v6.com")["upstream"],
        "2606:4700:4700::1111#853"
    );
    assert!(entry(&json, "cached.com")["upstream"].is_null());
}

#[tokio::test]
async fn local_record_answers_report_cache() {
    let pool = helpers::create_test_db().await;
    helpers::insert_local_dns_query(&pool, "nas.lan").await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    assert_eq!(entry(&json, "nas.lan")["status"], "CACHE");
}

#[tokio::test]
async fn types_outside_ftls_list_are_reported_by_number() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "caa.com",
            record_type: Some("CAA"),
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries").await;

    assert_eq!(entry(&json, "caa.com")["type"], "TYPE257");
}

#[tokio::test]
async fn first_page_cursor_pins_the_newest_row() {
    let pool = helpers::create_test_db().await;
    let mut newest = 0;
    for i in 0..5 {
        newest = insert_row(
            &pool,
            Row {
                domain: &format!("d{i}.com"),
                ..Default::default()
            },
        )
        .await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries?length=2").await;

    assert_eq!(json["cursor"], newest, "the first page pins the newest id");
    assert_eq!(ids(&json), vec![newest, newest - 1]);
}

#[tokio::test]
async fn cursor_and_start_page_through_the_pinned_snapshot() {
    let pool = helpers::create_test_db().await;
    let mut pin = 0;
    for i in 0..5 {
        pin = insert_row(
            &pool,
            Row {
                domain: &format!("d{i}.com"),
                ..Default::default()
            },
        )
        .await;
    }
    let app = helpers::create_pihole_test_app(pool.clone()).await;
    // Rows logged after the first page must not shift the later ones.
    insert_row(
        &pool,
        Row {
            domain: "late1.com",
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "late2.com",
            ..Default::default()
        },
    )
    .await;

    let (status, json) = get(&app, &format!("/queries?cursor={pin}&start=2&length=2")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["cursor"], pin, "a cursor sent is echoed back");
    assert_eq!(ids(&json), vec![pin - 2, pin - 3]);
}

#[tokio::test]
async fn cursor_past_the_newest_row_is_rejected() {
    let pool = helpers::create_test_db().await;
    let newest = insert_row(
        &pool,
        Row {
            domain: "a.com",
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = get(&app, &format!("/queries?cursor={}", newest + 10)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let reply = assert_ftl_shape::<ftl::ErrorReply>(&json);
    assert_eq!(reply.error.key, "bad_request");
    assert_eq!(reply.error.message, "Requested cursor is invalid");
}

#[tokio::test]
async fn non_positive_length_returns_every_row() {
    let pool = helpers::create_test_db().await;
    for i in 0..120 {
        insert_row(
            &pool,
            Row {
                domain: &format!("d{i}.com"),
                ..Default::default()
            },
        )
        .await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    for length in ["-1", "0"] {
        let (status, json) = get(&app, &format!("/queries?length={length}")).await;

        assert_eq!(status, StatusCode::OK, "length={length}");
        assert_eq!(ids(&json).len(), 120, "length={length} means all");
    }
}

#[tokio::test]
async fn unknown_filter_values_are_rejected() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    for (param, message) in [
        ("status", "Requested status is invalid"),
        ("type", "Requested type is invalid"),
        ("reply", "Requested reply is invalid"),
        ("dnssec", "Requested dnssec is invalid"),
    ] {
        let (status, json) = get(&app, &format!("/queries?{param}=NOPE")).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{param}");
        let reply = assert_ftl_shape::<ftl::ErrorReply>(&json);
        assert_eq!(reply.error.message, message);
        assert_eq!(reply.error.hint.as_deref(), Some("NOPE"));
    }
}

#[tokio::test]
async fn ftl_filters_narrow_the_log() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "a.com",
            client_ip: Some("10.0.0.7"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "b.com",
            record_type: Some("AAAA"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "c.com",
            dnssec_status: Some("Secure"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "d.com",
            dnssec_status: Some("Indeterminate"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "e.com",
            blocked: true,
            block_source: Some("blocklist"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "f.com",
            cache_hit: true,
            ..Default::default()
        },
    )
    .await;
    helpers::insert_upstream_query(&pool, "g.com", "default", "udp://9.9.9.9:53").await;
    let app = helpers::create_pihole_test_app(pool).await;

    for (query, expected) in [
        ("client_ip=10.0.0.7", vec!["a.com"]),
        ("client=10.0.0.7", vec!["a.com"]),
        ("type=AAAA", vec!["b.com"]),
        ("dnssec=SECURE", vec!["c.com"]),
        ("dnssec=ABANDONED", vec!["d.com"]),
        ("status=GRAVITY", vec!["e.com"]),
        ("status=cache", vec!["f.com"]),
        ("upstream=blocklist", vec!["e.com"]),
        ("upstream=9.9.9.9%2353", vec!["g.com"]),
        ("status=RETRIED", vec![]),
    ] {
        let (status, json) = get(&app, &format!("/queries?{query}")).await;

        assert_eq!(status, StatusCode::OK, "{query}");
        let domains: Vec<&str> = json["queries"]
            .as_array()
            .expect("queries")
            .iter()
            .filter_map(|q| q["domain"].as_str())
            .collect();
        assert_eq!(domains, expected, "{query}");
        assert_eq!(json["recordsFiltered"], expected.len(), "{query}");
    }
}

#[tokio::test]
async fn from_drops_older_queries() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "old.com",
            age: Some("-2 hours"),
            ..Default::default()
        },
    )
    .await;
    insert_row(
        &pool,
        Row {
            domain: "new.com",
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;
    let an_hour_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        - 3_600;

    let (_, json) = get(
        &app,
        &format!("/queries?from={an_hour_ago}&until=9999999999"),
    )
    .await;

    let domains: Vec<&str> = json["queries"]
        .as_array()
        .expect("queries")
        .iter()
        .filter_map(|q| q["domain"].as_str())
        .collect();
    assert_eq!(domains, vec!["new.com"]);
}

#[tokio::test]
async fn earliest_timestamps_report_the_oldest_query() {
    let pool = helpers::create_test_db().await;
    insert_row(
        &pool,
        Row {
            domain: "old.com",
            age: Some("-2 hours"),
            ..Default::default()
        },
    )
    .await;
    let app = helpers::create_pihole_test_app(pool).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs_f64();

    let (_, json) = get(&app, "/queries").await;

    for key in ["earliest_timestamp", "earliest_timestamp_disk"] {
        let earliest = json[key]
            .as_f64()
            .unwrap_or_else(|| panic!("{key} missing"));
        assert!(
            (now - 7_200.0 - earliest).abs() < 60.0,
            "{key} = {earliest}"
        );
    }
}

#[tokio::test]
async fn suggestions_match_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "a.com", "10.0.0.1", false, false, None).await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (status, json) = get(&app, "/queries/suggestions").await;

    assert_eq!(status, StatusCode::OK);
    let reply = assert_ftl_shape::<ftl::QueriesSuggestions>(&json);
    assert_eq!(reply.suggestions.domain, vec!["a.com"]);
    assert_eq!(reply.suggestions.client_ip, vec!["10.0.0.1"]);
}

#[tokio::test]
async fn suggestions_list_every_ftl_enum_value() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries/suggestions").await;

    let suggestions = &json["suggestions"];
    assert_eq!(
        suggestions["type"],
        serde_json::json!([
            "A", "AAAA", "ANY", "SRV", "SOA", "PTR", "TXT", "NAPTR", "MX", "DS", "RRSIG", "DNSKEY",
            "NS", "OTHER", "SVCB", "HTTPS"
        ])
    );
    assert_eq!(
        suggestions["status"],
        serde_json::json!([
            "UNKNOWN",
            "GRAVITY",
            "FORWARDED",
            "CACHE",
            "REGEX",
            "DENYLIST",
            "EXTERNAL_BLOCKED_IP",
            "EXTERNAL_BLOCKED_NULL",
            "EXTERNAL_BLOCKED_NXRA",
            "GRAVITY_CNAME",
            "REGEX_CNAME",
            "DENYLIST_CNAME",
            "RETRIED",
            "RETRIED_DNSSEC",
            "IN_PROGRESS",
            "DBBUSY",
            "SPECIAL_DOMAIN",
            "CACHE_STALE",
            "EXTERNAL_BLOCKED_EDE15"
        ])
    );
    assert_eq!(
        suggestions["reply"],
        serde_json::json!([
            "UNKNOWN", "NODATA", "NXDOMAIN", "CNAME", "IP", "DOMAIN", "RRNAME", "SERVFAIL",
            "REFUSED", "NOTIMP", "OTHER", "DNSSEC", "NONE", "BLOB"
        ])
    );
    assert_eq!(
        suggestions["dnssec"],
        serde_json::json!([
            "UNKNOWN",
            "SECURE",
            "INSECURE",
            "BOGUS",
            "ABANDONED",
            "TRUNCATED"
        ])
    );
}

#[tokio::test]
async fn suggested_upstreams_use_ip_hash_port() {
    let pool = helpers::create_test_db().await;
    helpers::insert_upstream_query(&pool, "a.com", "default", "udp://1.1.1.1:53").await;
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries/suggestions").await;

    assert_eq!(
        json["suggestions"]["upstream"],
        serde_json::json!(["blocklist", "cache", "1.1.1.1#53", "permitted"])
    );
}

#[tokio::test]
async fn suggestions_honour_count() {
    let pool = helpers::create_test_db().await;
    for i in 0..5 {
        helpers::insert_query(
            &pool,
            &format!("d{i}.com"),
            &format!("10.0.0.{i}"),
            false,
            false,
            None,
        )
        .await;
    }
    let app = helpers::create_pihole_test_app(pool).await;

    let (_, json) = get(&app, "/queries/suggestions?count=2").await;

    assert_eq!(
        json["suggestions"]["domain"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        json["suggestions"]["client_ip"].as_array().map(Vec::len),
        Some(2)
    );
}
