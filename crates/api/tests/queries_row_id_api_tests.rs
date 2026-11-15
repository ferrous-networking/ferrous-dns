//! `GET /queries` gives each row its query-log id, so a client polling the
//! log can tell the rows it already shows from new ones.
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{ClientProtocol, QueryLog, QuerySource, RecordType};
use helpers::{get_json, TestApp};
use serde_json::Value;
use std::time::Duration;

mod helpers;

fn query(domain: &str) -> QueryLog {
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
        cookie: None,
        doh_client_id: None,
    }
}

async fn logged(app: &TestApp, domains: &[&str]) -> Value {
    for domain in domains {
        app.query_log.log_query(&query(domain)).await.unwrap();
    }
    // Wait on the rows, not `total`: the handler reads the page and the count
    // concurrently, so a flush between the two gives a full count beside an
    // empty page.
    for _ in 0..40 {
        let json = get_json(app.router.clone(), "/queries").await;
        if json["data"].as_array().map_or(0, Vec::len) == domains.len() {
            return json;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the logged queries never reached the database");
}

fn ids(json: &Value) -> Vec<i64> {
    json["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| {
            q["id"]
                .as_i64()
                .unwrap_or_else(|| panic!("row without an id: {q}"))
        })
        .collect()
}

#[tokio::test]
async fn test_queries_give_each_row_a_distinct_id_newest_highest() {
    let app = TestApp::new().await;

    let json = logged(
        &app,
        &[
            "first.example.com",
            "second.example.com",
            "third.example.com",
        ],
    )
    .await;

    let ids = ids(&json);
    assert_eq!(ids.len(), 3, "{json}");
    // Newest first, so the ids fall down the page.
    assert!(
        ids.windows(2).all(|w| w[0] > w[1]),
        "ids not strictly descending: {ids:?}"
    );
}

#[tokio::test]
async fn test_a_row_keeps_its_id_across_reads() {
    let app = TestApp::new().await;
    let first = logged(&app, &["kept.example.com"]).await;

    let again = get_json(app.router.clone(), "/queries").await;

    assert_eq!(ids(&first), ids(&again));
}
