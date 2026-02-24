mod helpers;

use ferrous_dns_application::{ports::DnsResolution, use_cases::HandleDnsQueryUseCase};
use ferrous_dns_domain::{BlockSource, DnsRequest, DomainError, RecordType};
use helpers::{
    DnsResolutionBuilder, MockBlockFilterEngine, MockClientRepository, MockDnsResolver,
    MockQueryLogRepository,
};
use std::{net::IpAddr, sync::Arc};

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

fn make_use_case(
    resolver: Arc<MockDnsResolver>,
    filter: Arc<MockBlockFilterEngine>,
    log: Arc<MockQueryLogRepository>,
) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(resolver, filter, log)
}

fn upstream_resolution(ip: &str) -> DnsResolution {
    DnsResolution::new(vec![ip.parse().unwrap()], false)
}

fn cached_resolution(ip: &str) -> DnsResolution {
    DnsResolution::new(vec![ip.parse().unwrap()], true)
}

fn local_dns_resolution(ip: &str) -> DnsResolution {
    DnsResolution {
        local_dns: true,
        ..DnsResolution::new(vec![ip.parse().unwrap()], false)
    }
}

// ── execute: upstream path ─────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_upstream_resolution_logs_noerror() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("NOERROR"));
    assert!(!logs[0].cache_hit);
    assert!(!logs[0].blocked);
}

#[tokio::test]
async fn test_execute_local_dns_resolution_logs_local_dns_status() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("printer.lan", local_dns_resolution("192.168.1.10"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("printer.lan", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("LOCAL_DNS"));
}

// ── execute: block path ────────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_blocked_domain_returns_error_and_logs_blocked() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("ads.example.com");

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("ads.example.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].response_status, Some("BLOCKED"));
}

// ── execute: error paths ───────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_nxdomain_logs_nxdomain_status() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response_error("doesnotexist.com", DomainError::NxDomain)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("doesnotexist.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("NXDOMAIN"));
}

#[tokio::test]
async fn test_execute_timeout_logs_timeout_status() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response_error("slow.com", DomainError::QueryTimeout)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("slow.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::QueryTimeout)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("TIMEOUT"));
}

#[tokio::test]
async fn test_execute_generic_error_logs_servfail_status() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response_error(
            "broken.com",
            DomainError::InvalidDnsResponse("server error".into()),
        )
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("broken.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(result.is_err());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("SERVFAIL"));
}

#[tokio::test]
async fn test_execute_local_nxdomain_logs_local_dns_and_returns_nxdomain() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response_error("unknown.lan", DomainError::LocalNxDomain)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("unknown.lan", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("LOCAL_DNS"));
}

// ── execute: cache paths ───────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_cache_hit_logs_cache_hit_true() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver.set_cached_response("google.com", cached_resolution("8.8.8.8"));

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].cache_hit);
    assert_eq!(logs[0].response_status, Some("NOERROR"));
}

#[tokio::test]
async fn test_execute_negative_cache_hit_returns_nxdomain() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let negative = DnsResolution {
        cache_hit: true,
        ..DnsResolution::new(vec![], false)
    };
    resolver.set_cached_response("nxcached.com", negative);

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("nxcached.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].cache_hit);
    assert_eq!(logs[0].response_status, Some("NXDOMAIN"));
}

// ── try_cache_direct ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_try_cache_direct_returns_none_on_miss() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct("google.com", RecordType::A, CLIENT_IP);

    assert!(result.is_none());
    assert_eq!(log.sync_log_count(), 0);
}

#[tokio::test]
async fn test_try_cache_direct_returns_addresses_and_logs_on_hit() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver.set_cached_response("google.com", cached_resolution("8.8.8.8"));

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct("google.com", RecordType::A, CLIENT_IP);

    assert!(result.is_some());
    let (addresses, _ttl) = result.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].to_string(), "8.8.8.8");

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].cache_hit);
    assert_eq!(logs[0].response_status, Some("NOERROR"));
    assert_eq!(logs[0].client_ip, CLIENT_IP);
}

#[tokio::test]
async fn test_try_cache_direct_returns_none_when_cached_addresses_empty() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let empty = DnsResolution::new(vec![], true);
    resolver.set_cached_response("empty.com", empty);

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct("empty.com", RecordType::A, CLIENT_IP);

    assert!(result.is_none());
    assert_eq!(log.sync_log_count(), 0);
}

// ── client tracking ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_with_client_tracking_updates_last_seen() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());
    let client_repo = Arc::new(MockClientRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case =
        make_use_case(resolver, filter, log).with_client_tracking(client_repo.clone(), 0);
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    use_case.execute(&request).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let clients = client_repo.get_all_clients().await;
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].ip_address, CLIENT_IP);
    assert!(clients[0].query_count > 0);
}

#[tokio::test]
async fn test_execute_without_client_tracking_does_not_create_clients() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());
    let client_repo = Arc::new(MockClientRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case = make_use_case(resolver, filter, log);
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    use_case.execute(&request).await.unwrap();

    assert_eq!(client_repo.count().await, 0);
}

// ── CNAME cloaking detection ───────────────────────────────────────────────

#[tokio::test]
async fn test_cname_cloaking_blocked_upstream_path() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("x.tracker.com");

    let resolution = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .with_cname_chain(vec!["x.tracker.com"])
        .build();
    resolver
        .set_response("analytics.seusite.com", resolution)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("analytics.seusite.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].response_status, Some("BLOCKED"));
    assert_eq!(logs[0].block_source, Some(BlockSource::CnameCloaking));
}

#[tokio::test]
async fn test_cname_cloaking_blocked_then_cached_via_decision_cache() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("x.tracker.com");

    let upstream = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .with_cname_chain(vec!["x.tracker.com"])
        .build();
    resolver
        .set_response("analytics.seusite.com", upstream)
        .await;

    let use_case = make_use_case(Arc::clone(&resolver), Arc::clone(&filter), log.clone());
    let request = DnsRequest::new("analytics.seusite.com", RecordType::A, CLIENT_IP);

    let first = use_case.execute(&request).await;
    assert!(matches!(first, Err(DomainError::Blocked)));
    assert!(filter.is_cname_blocked("analytics.seusite.com"));

    let cached = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .cache_hit()
        .build();
    resolver.set_cached_response("analytics.seusite.com", cached);

    log.clear_sync_logs();

    let second = use_case.execute(&request).await;
    assert!(matches!(second, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].response_status, Some("BLOCKED"));
    assert_eq!(logs[0].block_source, Some(BlockSource::CnameCloaking));
}

#[tokio::test]
async fn test_cname_chain_middle_hop_blocked() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("x.tracker.com");

    let resolution = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .with_cname_chain(vec!["intermediate.cdn.com", "x.tracker.com"])
        .build();
    resolver
        .set_response("analytics.seusite.com", resolution)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("analytics.seusite.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].blocked);
    assert_eq!(logs[0].block_source, Some(BlockSource::CnameCloaking));
}

#[tokio::test]
async fn test_cname_chain_not_blocked_when_clean() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let resolution = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .with_cname_chain(vec!["safe.cdn.com"])
        .build();
    resolver
        .set_response("analytics.seusite.com", resolution)
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("analytics.seusite.com", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(result.is_ok());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(!logs[0].blocked);
}

#[tokio::test]
async fn test_try_cache_direct_returns_none_when_domain_blocked() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("analytics.seusite.com");

    let resolution = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .cache_hit()
        .build();
    resolver.set_cached_response("analytics.seusite.com", resolution);

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct("analytics.seusite.com", RecordType::A, CLIENT_IP);

    assert!(result.is_none());
    assert_eq!(log.sync_log_count(), 0);
}

// ── log metadata ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_execute_log_contains_correct_domain_and_record_type() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("example.com", upstream_resolution("93.184.216.34"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);

    use_case.execute(&request).await.unwrap();

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].domain.as_ref(), "example.com");
    assert_eq!(logs[0].record_type, RecordType::A);
    assert_eq!(logs[0].client_ip, CLIENT_IP);
}

#[tokio::test]
async fn test_execute_log_records_response_time() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    use_case.execute(&request).await.unwrap();

    let logs = log.get_sync_logs();
    assert!(logs[0].response_time_us.is_some());
}
