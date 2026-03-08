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
        entry.get("response_time").is_some(),
        "entry must have 'response_time'"
    );
    assert!(
        entry.get("upstream").is_some(),
        "entry must have 'upstream'"
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
async fn suggestions_returns_suggestions_array() {
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

    assert!(
        json["suggestions"].is_array(),
        "suggestions must be an array"
    );
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

    let suggestions = json["suggestions"].as_array().unwrap();
    let domains: Vec<&str> = suggestions.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        domains.contains(&"a.com"),
        "suggestions should contain 'a.com'"
    );
    assert!(
        domains.contains(&"b.com"),
        "suggestions should contain 'b.com'"
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

    let suggestions = json["suggestions"].as_array().unwrap();
    let dup_count = suggestions
        .iter()
        .filter(|v| v.as_str() == Some("dup.com"))
        .count();

    assert_eq!(
        dup_count, 1,
        "dup.com should appear exactly once, found {dup_count}"
    );
}
