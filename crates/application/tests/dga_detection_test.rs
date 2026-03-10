mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, DgaDetectionAction, DgaDetectionConfig, DnsRequest, DomainError, RecordType,
};
use helpers::{MockBlockFilterEngine, MockDgaFlagStore, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

fn dga_config(action: DgaDetectionAction) -> DgaDetectionConfig {
    DgaDetectionConfig {
        enabled: true,
        action,
        ..Default::default()
    }
}

fn make_use_case_with_dga(
    resolver: MockDnsResolver,
    config: &DgaDetectionConfig,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_dga_detection(config);
    (use_case, log)
}

fn make_use_case_with_flag_store(
    resolver: MockDnsResolver,
    config: &DgaDetectionConfig,
    store: Arc<MockDgaFlagStore>,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_dga_detection(config)
    .with_dga_flag_store(store);
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

// ── Phase 1: DGA guard (block action) ──────────────────────────────────────

#[tokio::test]
async fn high_entropy_sld_is_blocked() {
    let domain = "xjk4f9a2h3b5c7d.com";
    let resolver = resolver_with_response(domain).await;
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DgaDomainDetected)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::DgaDetection));
}

#[tokio::test]
async fn normal_domain_passes_dga_guard() {
    let resolver = resolver_with_response("google.com").await;
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Phase 1: alert action ───────────────────────────────────────────────────

#[tokio::test]
async fn alert_action_allows_dga_domain() {
    let domain = "xjk4f9a2h3b5c7d.com";
    let resolver = resolver_with_response(domain).await;
    let config = dga_config(DgaDetectionAction::Alert);
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok(), "alert mode should allow the query through");
}

// ── Disabled detection ──────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_dga_allows_everything() {
    let domain = "xjk4f9a2h3b5c7d.com";
    let resolver = resolver_with_response(domain).await;
    let config = DgaDetectionConfig {
        enabled: false,
        ..Default::default()
    };
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Short SLD skipped ───────────────────────────────────────────────────────

#[tokio::test]
async fn short_sld_passes_dga_guard() {
    let resolver = resolver_with_response("go.com").await;
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new("go.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Whitelisted domain ─────────────────────────────────────────────────────

#[tokio::test]
async fn whitelisted_domain_bypasses_dga() {
    let domain = "xjk4f9a2h3b5c7d.com";
    let resolver = resolver_with_response(domain).await;
    let config = DgaDetectionConfig {
        enabled: true,
        action: DgaDetectionAction::Block,
        domain_whitelist: vec![domain.to_string()],
        ..Default::default()
    };
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Whitelisted client ─────────────────────────────────────────────────────

#[tokio::test]
async fn whitelisted_client_bypasses_dga() {
    let domain = "xjk4f9a2h3b5c7d.com";
    let resolver = resolver_with_response(domain).await;
    let config = DgaDetectionConfig {
        enabled: true,
        action: DgaDetectionAction::Block,
        client_whitelist: vec!["192.168.1.0/24".to_string()],
        ..Default::default()
    };
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

// ── Flagged domain store ────────────────────────────────────────────────────

#[tokio::test]
async fn flagged_domain_is_blocked() {
    let resolver = resolver_with_response("dga.evil.com").await;
    let config = dga_config(DgaDetectionAction::Block);
    let store = Arc::new(MockDgaFlagStore::new());
    store.flag_domain("dga.evil.com");

    let (use_case, log) = make_use_case_with_flag_store(resolver, &config, store);

    let request = DnsRequest::new("dga.evil.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::DgaDomainDetected)));
    let logs = log.get_sync_logs();
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::DgaDetection));
}

#[tokio::test]
async fn unflagged_domain_passes_flag_store() {
    let resolver = resolver_with_response("safe.example.com").await;
    let config = dga_config(DgaDetectionAction::Block);
    let store = Arc::new(MockDgaFlagStore::new());

    let (use_case, _log) = make_use_case_with_flag_store(resolver, &config, store);

    let request = DnsRequest::new("safe.example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}
