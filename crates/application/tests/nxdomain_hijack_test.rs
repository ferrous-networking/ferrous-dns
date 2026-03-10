mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, DnsRequest, DomainError, NxdomainHijackAction, NxdomainHijackConfig, RecordType,
};
use helpers::{
    MockBlockFilterEngine, MockDnsResolver, MockNxdomainHijackIpStore, MockQueryLogRepository,
};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const HIJACK_IP: &str = "203.0.113.99";

fn hijack_config(action: NxdomainHijackAction) -> NxdomainHijackConfig {
    NxdomainHijackConfig {
        enabled: true,
        action,
        ..Default::default()
    }
}

fn make_use_case(
    resolver: MockDnsResolver,
    config: &NxdomainHijackConfig,
    store: Arc<MockNxdomainHijackIpStore>,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_nxdomain_hijack_detection(config, store);
    (use_case, log)
}

async fn resolver_with_ip(domain: &str, ip: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(domain, DnsResolution::new(vec![ip.parse().unwrap()], false))
        .await;
    resolver
}

// ── Block action ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn hijacked_response_is_blocked() {
    let resolver = resolver_with_ip("example.com", HIJACK_IP).await;
    let config = hijack_config(NxdomainHijackAction::Block);
    let store = Arc::new(MockNxdomainHijackIpStore::new());
    store.add_hijack_ip(HIJACK_IP.parse().unwrap());

    let (use_case, log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::NxdomainHijack));
    assert_eq!(logs[0].response_status, Some("NXDOMAIN_HIJACK"));
}

#[tokio::test]
async fn clean_response_passes_with_block_action() {
    let resolver = resolver_with_ip("example.com", "1.2.3.4").await;
    let config = hijack_config(NxdomainHijackAction::Block);
    let store = Arc::new(MockNxdomainHijackIpStore::new());
    store.add_hijack_ip(HIJACK_IP.parse().unwrap());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Alert action ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn hijacked_response_allowed_in_alert_mode() {
    let resolver = resolver_with_ip("example.com", HIJACK_IP).await;
    let config = hijack_config(NxdomainHijackAction::Alert);
    let store = Arc::new(MockNxdomainHijackIpStore::new());
    store.add_hijack_ip(HIJACK_IP.parse().unwrap());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok(), "alert mode should allow hijacked response");
}

// ── Disabled detection ────────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_detection_allows_hijacked_response() {
    let resolver = resolver_with_ip("example.com", HIJACK_IP).await;
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Cache direct path ─────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_hit_with_hijack_ip_falls_through() {
    let resolver = MockDnsResolver::new();
    let hijack_ip: IpAddr = HIJACK_IP.parse().unwrap();
    resolver.set_cached_response("cached.com", DnsResolution::new(vec![hijack_ip], true));
    resolver
        .set_response("cached.com", DnsResolution::new(vec![hijack_ip], false))
        .await;

    let config = hijack_config(NxdomainHijackAction::Block);
    let store = Arc::new(MockNxdomainHijackIpStore::new());
    store.add_hijack_ip(hijack_ip);

    let (use_case, log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("cached.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
    let logs = log.get_sync_logs();
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::NxdomainHijack));
}

// ── Empty store never blocks ──────────────────────────────────────────────────

#[tokio::test]
async fn empty_store_never_blocks() {
    let resolver = resolver_with_ip("example.com", "1.2.3.4").await;
    let config = hijack_config(NxdomainHijackAction::Block);
    let store = Arc::new(MockNxdomainHijackIpStore::new());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}
