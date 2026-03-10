mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, DnsRequest, DomainError, RecordType, ResponseIpFilterAction,
    ResponseIpFilterConfig,
};
use helpers::{
    MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository, MockResponseIpFilterStore,
};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const C2_IP: &str = "203.0.113.99";

fn filter_config(action: ResponseIpFilterAction) -> ResponseIpFilterConfig {
    ResponseIpFilterConfig {
        enabled: true,
        action,
        ..Default::default()
    }
}

fn make_use_case(
    resolver: MockDnsResolver,
    config: &ResponseIpFilterConfig,
    store: Arc<MockResponseIpFilterStore>,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_response_ip_filter(config, store);
    (use_case, log)
}

async fn resolver_with_ip(domain: &str, ip: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(domain, DnsResolution::new(vec![ip.parse().unwrap()], false))
        .await;
    resolver
}

// ── Block action ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn blocked_c2_ip_returns_error() {
    let resolver = resolver_with_ip("malware.com", C2_IP).await;
    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(C2_IP.parse().unwrap());

    let (use_case, log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("malware.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::ResponseIpFilter));
    assert_eq!(logs[0].response_status, Some("RESPONSE_IP_BLOCKED"));
}

#[tokio::test]
async fn clean_response_passes_with_block_action() {
    let resolver = resolver_with_ip("safe.com", "1.2.3.4").await;
    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(C2_IP.parse().unwrap());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("safe.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Alert action ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn c2_ip_allowed_in_alert_mode() {
    let resolver = resolver_with_ip("malware.com", C2_IP).await;
    let config = filter_config(ResponseIpFilterAction::Alert);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(C2_IP.parse().unwrap());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("malware.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok(), "alert mode should allow C2 IP response");
}

// ── Disabled detection ───────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_detection_allows_c2_response() {
    let resolver = resolver_with_ip("malware.com", C2_IP).await;
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    );

    let request = DnsRequest::new("malware.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Cache direct path ────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_hit_with_c2_ip_falls_through() {
    let resolver = MockDnsResolver::new();
    let c2_ip: IpAddr = C2_IP.parse().unwrap();
    resolver.set_cached_response("cached.com", DnsResolution::new(vec![c2_ip], true));
    resolver
        .set_response("cached.com", DnsResolution::new(vec![c2_ip], false))
        .await;

    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(c2_ip);

    let (use_case, log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("cached.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::ResponseIpFilter));
}

// ── Empty store never blocks ─────────────────────────────────────────────────

#[tokio::test]
async fn empty_store_never_blocks() {
    let resolver = resolver_with_ip("example.com", "1.2.3.4").await;
    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Multiple IPs in response ─────────────────────────────────────────────────

#[tokio::test]
async fn blocks_when_one_of_multiple_ips_is_c2() {
    let resolver = MockDnsResolver::new();
    let c2_ip: IpAddr = C2_IP.parse().unwrap();
    let clean_ip: IpAddr = "1.2.3.4".parse().unwrap();
    resolver
        .set_response(
            "multi.com",
            DnsResolution::new(vec![clean_ip, c2_ip], false),
        )
        .await;

    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(c2_ip);

    let (use_case, log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("multi.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::ResponseIpFilter));
}

#[tokio::test]
async fn passes_when_no_ips_match_c2_list() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "multi.com",
            DnsResolution::new(
                vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
                false,
            ),
        )
        .await;

    let config = filter_config(ResponseIpFilterAction::Block);
    let store = Arc::new(MockResponseIpFilterStore::new());
    store.add_blocked_ip(C2_IP.parse().unwrap());

    let (use_case, _log) = make_use_case(resolver, &config, store);

    let request = DnsRequest::new("multi.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}
