//! The `dns64_synthesized` query-log tag is DERIVED at log time from NAT64-prefix
//! membership (not carried on `DnsResolution`). These tests pin that derivation as
//! it threads through `HandleDnsQueryUseCase::execute` into the logged `QueryLog`:
//! only an AAAA answer whose addresses all fall in the configured prefix is tagged.

mod helpers;

use ferrous_dns_application::{ports::DnsResolution, use_cases::HandleDnsQueryUseCase};
use ferrous_dns_domain::{DnsRequest, RecordType};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
// 93.184.216.34 embedded in the well-known NAT64 /96 (last 32 bits = 5db8:d822).
const SYNTHESIZED_AAAA: &str = "64:ff9b::5db8:d822";
// A real, globally-routed AAAA outside the prefix.
const REAL_AAAA: &str = "2606:2800:220:1:248:1893:25c8:1946";

fn resolution(ip: &str) -> DnsResolution {
    DnsResolution::new(vec![ip.parse::<IpAddr>().unwrap()], false)
}

fn use_case_with_dns64(
    resolver: Arc<MockDnsResolver>,
    log: Arc<MockQueryLogRepository>,
) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(resolver, Arc::new(MockBlockFilterEngine::new()), log)
        .with_dns64("64:ff9b::".parse::<Ipv6Addr>().unwrap())
}

#[tokio::test]
async fn aaaa_answer_inside_prefix_is_tagged_synthesized() {
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver
        .set_response("example.com", resolution(SYNTHESIZED_AAAA))
        .await;

    let use_case = use_case_with_dns64(resolver, log.clone());
    let request = DnsRequest::new("example.com", RecordType::AAAA, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(
        logs[0].dns64_synthesized,
        "AAAA answer inside the NAT64 prefix must be tagged"
    );
}

#[tokio::test]
async fn real_aaaa_outside_prefix_is_not_tagged() {
    // The false-positive guard: a genuine AAAA that happens to be served while
    // DNS64 is enabled must NOT be flagged as synthesized.
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver
        .set_response("example.com", resolution(REAL_AAAA))
        .await;

    let use_case = use_case_with_dns64(resolver, log.clone());
    let request = DnsRequest::new("example.com", RecordType::AAAA, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert!(!log.get_sync_logs()[0].dns64_synthesized);
}

#[tokio::test]
async fn a_record_answer_is_never_tagged() {
    // The record-type gate: only AAAA can be synthesized, so an A answer is never
    // tagged even though DNS64 is enabled.
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver
        .set_response("example.com", resolution("93.184.216.34"))
        .await;

    let use_case = use_case_with_dns64(resolver, log.clone());
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert!(!log.get_sync_logs()[0].dns64_synthesized);
}

#[tokio::test]
async fn aaaa_in_prefix_is_not_tagged_when_dns64_disabled() {
    // Without `.with_dns64`, the prefix is absent and nothing is ever tagged, even
    // for an address that would otherwise match the well-known prefix.
    let resolver = Arc::new(MockDnsResolver::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver
        .set_response("example.com", resolution(SYNTHESIZED_AAAA))
        .await;

    let use_case = HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );
    let request = DnsRequest::new("example.com", RecordType::AAAA, CLIENT_IP);
    use_case.execute(&request).await.unwrap();

    assert!(!log.get_sync_logs()[0].dns64_synthesized);
}
