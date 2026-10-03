//! Work shed under overload reaches `GET /metrics`: each drop path the API
//! process can reach records into the counter the scrape reads.

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_api::metrics_routes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsQuery, DnsRequest, DomainError, QueryLog, QuerySource, RecordType};
use helpers::stubs::NullBlockFilterEngine;
use helpers::TestApp;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

async fn scrape(app: &TestApp) -> String {
    let response = metrics_routes(app.state.clone())
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

/// The value of the sample `name` in the exposition `body`.
fn sample(body: &str, name: &str) -> Option<u64> {
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

fn logged_query() -> QueryLog {
    QueryLog {
        id: None,
        domain: "example.com".into(),
        record_type: RecordType::A,
        client_ip: "10.0.0.1".parse().unwrap(),
        client_hostname: None,
        blocked: false,
        response_time_us: Some(100),
        cache_hit: false,
        cache_refresh: false,
        dnssec_status: None,
        dns64_synthesized: false,
        answers: None,
        upstream_server: None,
        upstream_pool: None,
        response_status: Some("NOERROR"),
        timestamp: None,
        query_source: QuerySource::Client,
        protocol: None,
        group_id: None,
        block_source: None,
    }
}

#[tokio::test]
async fn query_log_entries_dropped_on_a_full_channel_are_scraped() {
    let app = TestApp::builder()
        .query_log_channel_capacity(1)
        .build()
        .await;
    assert_eq!(
        sample(&scrape(&app).await, "ferrousdns_query_log_dropped_total"),
        Some(0)
    );

    // Nothing yields in between, so the flush task cannot drain the channel:
    // the first entry fills it and the other two are dropped.
    for _ in 0..3 {
        app.query_log.log_query_sync(&logged_query()).unwrap();
    }

    let body = scrape(&app).await;
    assert_eq!(sample(&body, "ferrousdns_query_log_dropped_total"), Some(2));
    assert_eq!(sample(&body, "ferrousdns_upstream_shed_total"), Some(0));
    assert_eq!(sample(&body, "ferrousdns_udp_fallback_shed_total"), Some(0));
}

/// Every query reaches past the cache and asks for an upstream slot.
struct Unreachable;

#[async_trait]
impl DnsResolver for Unreachable {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        unreachable!("a shed query never reaches the resolver")
    }
}

#[tokio::test]
async fn queries_shed_for_lack_of_an_upstream_slot_are_scraped() {
    let app = TestApp::new().await;
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(Unreachable),
        Arc::new(NullBlockFilterEngine),
        app.query_log.clone(),
    )
    .with_upstream_limit(0, app.state.dns.shed.upstream.clone());

    for domain in ["a.example.com", "b.example.com"] {
        let request = DnsRequest::new(domain, RecordType::A, "10.0.0.1".parse().unwrap());
        assert!(matches!(
            use_case.execute(&request).await,
            Err(DomainError::UpstreamCapacityExhausted)
        ));
    }

    let body = scrape(&app).await;
    assert_eq!(sample(&body, "ferrousdns_upstream_shed_total"), Some(2));
    assert_eq!(sample(&body, "ferrousdns_query_log_dropped_total"), Some(0));
}
