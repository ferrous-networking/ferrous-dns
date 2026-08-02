//! `QueryLog::answers` carries the resolved A/AAAA addresses so the query log UI
//! can show what a domain actually resolved to. These tests pin which paths
//! through `HandleDnsQueryUseCase` populate it — and which leave it empty.

mod helpers;

use ferrous_dns_application::{ports::DnsResolution, use_cases::HandleDnsQueryUseCase};
use ferrous_dns_domain::{DnsRequest, RecordType};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

fn resolution(ips: &[&str]) -> DnsResolution {
    DnsResolution::new(
        ips.iter().map(|ip| ip.parse::<IpAddr>().unwrap()).collect(),
        false,
    )
}

fn logged_answers(log: &MockQueryLogRepository) -> Vec<String> {
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1, "expected exactly one logged query");
    logs[0]
        .answers
        .as_ref()
        .map(|a| a.iter().map(|ip| ip.to_string()).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn upstream_answer_addresses_are_logged() {
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver
        .set_response(
            "example.com",
            resolution(&["93.184.216.34", "93.184.216.35"]),
        )
        .await;

    let use_case = HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert_eq!(logged_answers(&log), ["93.184.216.34", "93.184.216.35"]);
}

#[tokio::test]
async fn cache_hit_answer_addresses_are_logged() {
    // The cache branch returns before the resolver is consulted, so it has to
    // carry the addresses of the cached resolution on its own.
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver.set_cached_response("example.com", resolution(&["93.184.216.34"]));

    let use_case = HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert_eq!(logged_answers(&log), ["93.184.216.34"]);
}

#[tokio::test]
async fn blocked_query_logs_no_answers() {
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    let block_filter = Arc::new(MockBlockFilterEngine::new());
    block_filter.block_domain("ads.example.com");

    let use_case = HandleDnsQueryUseCase::new(resolver, block_filter, log.clone());
    let request = DnsRequest::new("ads.example.com", RecordType::A, CLIENT_IP);
    assert!(use_case.execute(&request).await.is_err());

    assert!(log.get_sync_logs()[0].answers.is_none());
}

#[tokio::test]
async fn answerless_resolution_logs_no_addresses() {
    // A record type with no address answer (HTTPS, TXT, ...) resolves fine but
    // has nothing to show in the ANSWER column.
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver.set_response("example.com", resolution(&[])).await;

    let use_case = HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );
    let request = DnsRequest::new("example.com", RecordType::HTTPS, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert!(logged_answers(&log).is_empty());
}
