mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, ClientProtocol, DgaDetectionAction, DgaDetectionConfig, DnsRequest, DomainError,
    RecordType,
};
use helpers::fast_path::{resolver_with_cached_ip, resolver_with_cached_wire, served, served_wire};
use helpers::{MockBlockFilterEngine, MockDgaFlagStore, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
/// Trips the DGA guard's hot-path scoring on its own.
const DGA_SHAPED: &str = "xjk4f9a2h3b5c7d.com";

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

#[tokio::test]
async fn short_sld_passes_dga_guard() {
    let resolver = resolver_with_response("go.com").await;
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let request = DnsRequest::new("go.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
}

/// At the default threshold the hot-path score needs two or more signals: one
/// alone (length, entropy) never blocks, real CDN names pass, and only the
/// SLD is scored, under a compound suffix too.
#[tokio::test]
async fn the_hot_path_score_blocks_only_names_that_fire_several_signals() {
    let long_repetitive = format!("{}.com", "a".repeat(25));
    let long_random = format!("{}xbkrwtplmqzncdf.com", "r".repeat(10));
    let cases = [
        ("cloudflare.com", false),
        ("fastly.net", false),
        ("gstatic.com", false),
        ("fbcdn.net", false),
        ("twimg.com", false),
        ("githubusercontent.com", false),
        ("akamaized.net", false),
        (long_repetitive.as_str(), false),
        ("xjk4f9a2h3b5c7d.example.com", false),
        ("bcdfghjklmnpqrst.com", true),
        (long_random.as_str(), true),
        ("xjk4f9a2h3b5c7d.co.uk", true),
    ];
    for (domain, blocked) in cases {
        let config = dga_config(DgaDetectionAction::Block);
        let (use_case, _log) =
            make_use_case_with_dga(resolver_with_response(domain).await, &config);
        let result = use_case
            .execute(&DnsRequest::new(domain, RecordType::A, CLIENT_IP))
            .await;
        assert_eq!(
            matches!(result, Err(DomainError::DgaDomainDetected)),
            blocked,
            "{domain}: {result:?}"
        );
    }
}

/// The guard skips the entropy when it cannot reach the threshold, so a
/// threshold the entropy alone meets must still see it.
#[tokio::test]
async fn entropy_alone_blocks_when_the_threshold_is_its_weight() {
    // High entropy (3.17 bits), a normal consonant ratio and no digits.
    let domain = "aeioubcdf.com";
    let config = DgaDetectionConfig {
        hot_path_confidence_threshold: 0.30,
        sld_entropy_threshold: 3.0,
        ..dga_config(DgaDetectionAction::Block)
    };
    let (use_case, _log) = make_use_case_with_dga(resolver_with_response(domain).await, &config);
    let request = DnsRequest::new(domain, RecordType::A, CLIENT_IP);
    assert!(matches!(
        use_case.execute(&request).await,
        Err(DomainError::DgaDomainDetected)
    ));

    let config = DgaDetectionConfig {
        hot_path_confidence_threshold: 0.31,
        ..config
    };
    let (use_case, _log) = make_use_case_with_dga(resolver_with_response(domain).await, &config);
    assert!(use_case.execute(&request).await.is_ok(), "0.30 < 0.31");
}

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

/// A cache hit used to skip the phase-1 check, so a DGA-shaped name that
/// anyone had resolved was served to every client until its TTL ran out.
#[tokio::test]
async fn the_fast_path_does_not_serve_a_cached_dga_shaped_name() {
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, log) =
        make_use_case_with_dga(resolver_with_cached_ip(DGA_SHAPED, "1.2.3.4"), &config);

    let result = use_case.try_cache_direct(
        DGA_SHAPED,
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(result.is_none(), "the fast path served it: {result:?}");
    assert_eq!(
        log.sync_log_count(),
        0,
        "execute logs the block, not the probe"
    );
    let request = DnsRequest::new(DGA_SHAPED, RecordType::A, CLIENT_IP);
    assert!(matches!(
        use_case.execute(&request).await,
        Err(DomainError::DgaDomainDetected)
    ));
}

#[tokio::test]
async fn the_wire_fast_path_does_not_serve_a_cached_dga_shaped_name() {
    let config = dga_config(DgaDetectionAction::Block);
    let (use_case, log) = make_use_case_with_dga(resolver_with_cached_wire(DGA_SHAPED), &config);

    let result = use_case.try_cache_wire_direct(
        DGA_SHAPED,
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        served_wire,
    );

    assert!(result.is_none(), "the wire fast path served it: {result:?}");
    assert_eq!(log.sync_log_count(), 0);
}

/// Alert mode resolves the name, but on the slow path, where the alert is
/// raised; the fast path would serve it silently.
#[tokio::test]
async fn the_fast_path_leaves_an_alert_mode_hit_to_execute() {
    let resolver = resolver_with_cached_ip(DGA_SHAPED, "1.2.3.4");
    resolver
        .set_response(
            DGA_SHAPED,
            DnsResolution::new(vec!["1.2.3.4".parse().unwrap()], false),
        )
        .await;
    let config = dga_config(DgaDetectionAction::Alert);
    let (use_case, _log) = make_use_case_with_dga(resolver, &config);

    let result = use_case.try_cache_direct(
        DGA_SHAPED,
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(result.is_none(), "the fast path served it: {result:?}");
    let request = DnsRequest::new(DGA_SHAPED, RecordType::A, CLIENT_IP);
    assert!(use_case.execute(&request).await.is_ok());
}

#[tokio::test]
async fn the_fast_path_serves_a_cached_dga_shaped_name_that_is_explicitly_allowed() {
    let filter = MockBlockFilterEngine::new();
    filter.allow_domain(DGA_SHAPED);
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver_with_cached_ip(DGA_SHAPED, "1.2.3.4")),
        Arc::new(filter),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_dga_detection(&dga_config(DgaDetectionAction::Block));

    let result = use_case.try_cache_direct(
        DGA_SHAPED,
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(
        result.is_some(),
        "an allowed name must stay on the fast path"
    );
}
