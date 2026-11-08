//! `GET /queries` reports what each query's DNS Cookie showed, and filters on
//! it with `cookie=any|valid|client|invalid|none`.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{ClientProtocol, CookieStatus, QueryLog, QuerySource, RecordType};
use helpers::{get_json, TestApp};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;
use tower::ServiceExt;

mod helpers;

fn query(domain: &str, cookie: Option<CookieStatus>) -> QueryLog {
    QueryLog {
        id: None,
        domain: domain.into(),
        record_type: RecordType::A,
        client_ip: "192.168.1.50".parse().unwrap(),
        client_hostname: None,
        blocked: false,
        response_time_us: Some(40),
        cache_hit: true,
        cache_refresh: false,
        dnssec_status: None,
        dns64_synthesized: false,
        answers: None,
        upstream_server: None,
        upstream_pool: None,
        response_status: Some("NOERROR"),
        timestamp: None,
        query_source: QuerySource::Client,
        protocol: Some(ClientProtocol::Udp),
        group_id: None,
        block_source: None,
        coalesced: None,
        cookie,
        doh_client_id: None,
    }
}

/// An app whose query log holds one row per cookie status, and one without.
async fn seeded() -> TestApp {
    let app = TestApp::new().await;
    for (domain, cookie) in [
        ("valid.example.com", Some(CookieStatus::Valid)),
        ("client.example.com", Some(CookieStatus::ClientOnly)),
        ("invalid.example.com", Some(CookieStatus::Invalid)),
        ("none.example.com", None),
    ] {
        app.query_log
            .log_query(&query(domain, cookie))
            .await
            .unwrap();
    }
    for _ in 0..40 {
        let json = get_json(app.router.clone(), "/queries").await;
        if json["total"] == 4 {
            return app;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the seeded queries never reached the database");
}

fn domains(json: &Value) -> BTreeSet<String> {
    json["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["domain"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn test_queries_report_the_dns_cookie_status() {
    let app = seeded().await;

    let json = get_json(app.router.clone(), "/queries").await;

    let cookie_of = |domain: &str| {
        json["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|q| q["domain"] == domain)
            .unwrap_or_else(|| panic!("{domain} missing: {json}"))["cookie"]
            .clone()
    };
    assert_eq!(cookie_of("valid.example.com"), "valid");
    assert_eq!(cookie_of("client.example.com"), "client");
    assert_eq!(cookie_of("invalid.example.com"), "invalid");
    assert_eq!(cookie_of("none.example.com"), Value::Null);
}

#[tokio::test]
async fn test_queries_filter_by_dns_cookie() {
    let app = seeded().await;

    for (filter, expected) in [
        (
            "any",
            &[
                "client.example.com",
                "invalid.example.com",
                "valid.example.com",
            ][..],
        ),
        ("valid", &["valid.example.com"][..]),
        ("client", &["client.example.com"][..]),
        ("invalid", &["invalid.example.com"][..]),
        ("none", &["none.example.com"][..]),
    ] {
        let json = get_json(app.router.clone(), &format!("/queries?cookie={filter}")).await;
        let expected: BTreeSet<String> = expected.iter().map(|d| d.to_string()).collect();
        assert_eq!(domains(&json), expected, "cookie={filter}");
        assert_eq!(json["total"], expected.len(), "cookie={filter}");
    }
}

#[tokio::test]
async fn test_queries_reject_an_unknown_cookie_filter() {
    let app = TestApp::new().await;

    let response = app
        .router
        .oneshot(
            Request::builder()
                .uri("/queries?cookie=stale")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
