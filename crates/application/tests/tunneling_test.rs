mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, DnsRequest, DomainError, RecordType, TunnelingAction, TunnelingDetectionConfig,
};
use helpers::{
    MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository, MockTunnelingFlagStore,
};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

fn tunneling_config(action: TunnelingAction) -> TunnelingDetectionConfig {
    TunnelingDetectionConfig {
        enabled: true,
        action,
        max_fqdn_length: 120,
        max_label_length: 50,
        block_null_queries: true,
        ..Default::default()
    }
}

fn make_use_case_with_tunneling(
    resolver: MockDnsResolver,
    config: &TunnelingDetectionConfig,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_tunneling_detection(config);
    (use_case, log)
}

fn make_use_case_with_flag_store(
    resolver: MockDnsResolver,
    config: &TunnelingDetectionConfig,
    store: Arc<MockTunnelingFlagStore>,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_tunneling_detection(config)
    .with_tunneling_flag_store(store);
    (use_case, log)
}

async fn resolver_with_response(domain: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            domain,
            DnsResolution::new(vec!["1.2.3.4".parse().unwrap()], false),
        )
        .await;
    resolver
}

// ── Phase 1: hot-path guard (block action) ──────────────────────────────────

#[tokio::test]
async fn long_fqdn_is_blocked() {
    let long_domain = format!("{}.evil.com", "a".repeat(120));
    let resolver = resolver_with_response(&long_domain).await;
    let config = tunneling_config(TunnelingAction::Block);
    let (use_case, log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new(long_domain.as_str(), RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DnsTunnelingDetected)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::DnsTunneling));
}

#[tokio::test]
async fn long_label_is_blocked() {
    let domain = format!("{}.evil.com", "b".repeat(51));
    let resolver = resolver_with_response(&domain).await;
    let config = tunneling_config(TunnelingAction::Block);
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new(domain.as_str(), RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DnsTunnelingDetected)));
}

#[tokio::test]
async fn null_record_type_is_blocked() {
    let resolver = resolver_with_response("example.com").await;
    let config = tunneling_config(TunnelingAction::Block);
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new("example.com", RecordType::NULL, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DnsTunnelingDetected)));
}

#[tokio::test]
async fn normal_domain_passes_tunneling_guard() {
    let resolver = resolver_with_response("example.com").await;
    let config = tunneling_config(TunnelingAction::Block);
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Phase 1: alert action ───────────────────────────────────────────────────

#[tokio::test]
async fn alert_action_allows_long_fqdn() {
    let long_domain = format!("{}.evil.com", "a".repeat(120));
    let resolver = resolver_with_response(&long_domain).await;
    let config = tunneling_config(TunnelingAction::Alert);
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new(long_domain.as_str(), RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok(), "alert mode should allow the query through");
}

// ── Disabled tunneling ──────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_tunneling_allows_everything() {
    let long_domain = format!("{}.evil.com", "a".repeat(200));
    let resolver = resolver_with_response(&long_domain).await;
    let config = TunnelingDetectionConfig {
        enabled: false,
        ..Default::default()
    };
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new(long_domain.as_str(), RecordType::NULL, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Whitelisted domains ─────────────────────────────────────────────────────

#[tokio::test]
async fn whitelisted_domain_bypasses_guard() {
    let long_domain = format!("{}.cdn.example.com", "a".repeat(120));
    let resolver = resolver_with_response(&long_domain).await;
    let config = TunnelingDetectionConfig {
        enabled: true,
        action: TunnelingAction::Block,
        domain_whitelist: vec![long_domain.clone()],
        ..Default::default()
    };
    let (use_case, _log) = make_use_case_with_tunneling(resolver, &config);

    let request = DnsRequest::new(long_domain.as_str(), RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Flagged domain store ────────────────────────────────────────────────────

#[tokio::test]
async fn flagged_domain_is_blocked() {
    let resolver = resolver_with_response("tunnel.evil.com").await;
    let config = tunneling_config(TunnelingAction::Block);
    let store = Arc::new(MockTunnelingFlagStore::new());
    store.flag_domain("tunnel.evil.com");

    let (use_case, log) = make_use_case_with_flag_store(resolver, &config, store);

    let request = DnsRequest::new("tunnel.evil.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DnsTunnelingDetected)));
    let logs = log.get_sync_logs();
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::DnsTunneling));
}

#[tokio::test]
async fn unflagged_domain_passes_flag_store() {
    let resolver = resolver_with_response("safe.example.com").await;
    let config = tunneling_config(TunnelingAction::Block);
    let store = Arc::new(MockTunnelingFlagStore::new());

    let (use_case, _log) = make_use_case_with_flag_store(resolver, &config, store);

    let request = DnsRequest::new("safe.example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn flagged_domain_with_alert_action_allows_query() {
    let resolver = resolver_with_response("tunnel.evil.com").await;
    let config = tunneling_config(TunnelingAction::Alert);
    let store = Arc::new(MockTunnelingFlagStore::new());
    store.flag_domain("tunnel.evil.com");

    let (use_case, _log) = make_use_case_with_flag_store(resolver, &config, store);

    let request = DnsRequest::new("tunnel.evil.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok(), "alert mode should allow flagged domain");
}

// ── Event emission ──────────────────────────────────────────────────────────

#[tokio::test]
async fn tunneling_event_is_emitted_after_resolution() {
    let resolver = resolver_with_response("example.com").await;
    let config = tunneling_config(TunnelingAction::Block);

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log,
    )
    .with_tunneling_detection(&config)
    .with_tunneling_event_sender(tx);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());

    let event = rx.try_recv().expect("expected tunneling event");
    assert_eq!(&*event.domain, "example.com");
    assert_eq!(event.record_type, RecordType::A);
    assert!(!event.was_nxdomain);
}
