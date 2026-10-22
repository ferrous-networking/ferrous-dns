mod helpers;

use async_trait::async_trait;
use ferrous_dns_application::{
    ports::{DnsResolution, SafeSearchEnginePort},
    use_cases::HandleDnsQueryUseCase,
};
use ferrous_dns_domain::{BlockSource, ClientProtocol, DnsRequest, DomainError, RecordType};
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
        local_nxdomain: false,
        ..DnsResolution::new(vec![ip.parse().unwrap()], false)
    }
}

/// A fast-path `respond` that serves every A/AAAA hit.
fn served(addresses: &[IpAddr], ttl: u32) -> Option<(Vec<IpAddr>, u32)> {
    Some((addresses.to_vec(), ttl))
}

/// A fast-path `respond` that serves every wire hit.
fn served_wire(wire: &[u8], remaining: u32) -> Option<(Vec<u8>, u32)> {
    Some((wire.to_vec(), remaining))
}

/// A cached wire answer for `mail.example.com`, as the cache layer reports it.
fn cached_wire_resolution() -> DnsResolution {
    DnsResolution {
        upstream_wire_data: Some(bytes::Bytes::from_static(b"\x00\x01\x02\x03")),
        min_ttl: Some(300),
        ..DnsResolution::new(vec![], true)
    }
}

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

/// `block_non_fqdn` and `block_private_ptr` refuse a name with `FilteredQuery`,
/// and the server answers it with the blocked response (0.0.0.0 + EDE 15), so
/// the log must record a block, not a SERVFAIL the client never saw.
#[tokio::test]
async fn test_execute_filtered_query_logs_blocked_with_source() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response_error(
            "omada",
            DomainError::FilteredQuery("Non-FQDN query blocked: omada".into()),
        )
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("omada", RecordType::A, CLIENT_IP);

    let result = use_case.execute(&request).await;

    assert!(matches!(result, Err(DomainError::FilteredQuery(_))));
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].response_status, Some("BLOCKED"));
    assert!(logs[0].blocked);
    assert!(logs[0].block_source.is_some());
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

#[tokio::test]
async fn test_try_cache_direct_returns_none_on_miss() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct(
        "google.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

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

    let result = use_case.try_cache_direct(
        "google.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(result.is_some());
    let (addresses, _ttl) = result.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].to_string(), "8.8.8.8");

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].cache_hit);
    assert_eq!(logs[0].response_status, Some("NOERROR"));
    assert_eq!(logs[0].client_ip, CLIENT_IP);
    assert_eq!(logs[0].protocol, Some(ClientProtocol::Udp));
}

/// The fast path must log whatever transport it was handed rather than
/// assuming UDP, so a future non-UDP caller is labelled correctly.
#[tokio::test]
async fn test_try_cache_direct_logs_the_protocol_it_was_given() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver.set_cached_response("google.com", cached_resolution("8.8.8.8"));

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct(
        "google.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Dot,
        served,
    );

    assert!(result.is_some());
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].protocol, Some(ClientProtocol::Dot));
}

/// The slow path carries the transport from the `DnsRequest` the listener
/// built, and leaves it unset when no listener recorded one.
#[tokio::test]
async fn test_execute_logs_the_request_protocol() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request =
        DnsRequest::new("google.com", RecordType::A, CLIENT_IP).with_protocol(ClientProtocol::Doq);

    assert!(use_case.execute(&request).await.is_ok());

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].protocol, Some(ClientProtocol::Doq));
}

#[tokio::test]
async fn test_execute_leaves_protocol_unset_when_request_has_none() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver
        .set_response("google.com", upstream_resolution("8.8.8.8"))
        .await;

    let use_case = make_use_case(resolver, filter, log.clone());
    let request = DnsRequest::new("google.com", RecordType::A, CLIENT_IP);

    assert!(use_case.execute(&request).await.is_ok());

    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].protocol, None);
}

#[tokio::test]
async fn test_try_cache_direct_returns_none_when_cached_addresses_empty() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let empty = DnsResolution::new(vec![], true);
    resolver.set_cached_response("empty.com", empty);

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_direct(
        "empty.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(result.is_none());
    assert_eq!(log.sync_log_count(), 0);
}

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

    let result = use_case.try_cache_direct(
        "analytics.seusite.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        served,
    );

    assert!(result.is_none());
    assert_eq!(log.sync_log_count(), 0);
}

#[test]
fn try_cache_wire_direct_returns_none_on_cache_miss() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let use_case = make_use_case(resolver, filter, log);

    let result = use_case.try_cache_wire_direct(
        "example.com",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        served_wire,
    );

    assert!(result.is_none());
}

#[test]
fn try_cache_wire_direct_hands_a_hit_and_what_its_entry_has_left_to_respond() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    resolver.set_cached_response("mail.example.com", cached_wire_resolution());

    let use_case = make_use_case(resolver, filter, log.clone());

    let result = use_case.try_cache_wire_direct(
        "mail.example.com",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        served_wire,
    );

    assert_eq!(result, Some((b"\x00\x01\x02\x03".to_vec(), 300)));
    assert_eq!(log.sync_log_count(), 1);
}

/// A hit the server cannot answer inline (too big for the client, or a
/// relay that fails) goes to `execute`, which logs it: the fast path must
/// not have logged it already.
#[tokio::test]
async fn fast_path_hits_declined_by_the_server_are_logged_once_by_the_slow_path() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());
    resolver.set_cached_response("mail.example.com", cached_wire_resolution());
    resolver.set_cached_response("google.com", cached_resolution("8.8.8.8"));
    let use_case = make_use_case(resolver, filter, log.clone());

    let declined = use_case.try_cache_wire_direct(
        "mail.example.com",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| None::<()>,
    );
    assert!(declined.is_none());
    let declined = use_case.try_cache_direct(
        "google.com",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| None::<()>,
    );
    assert!(declined.is_none());
    assert_eq!(log.sync_log_count(), 0, "a declined hit is not logged");

    for (domain, record_type) in [
        ("mail.example.com", RecordType::MX),
        ("google.com", RecordType::A),
    ] {
        let request = DnsRequest::new(domain, record_type, CLIENT_IP);
        assert!(use_case.execute(&request).await.is_ok());
    }
    let logs = log.get_sync_logs();
    assert_eq!(logs.len(), 2);
    assert!(logs.iter().all(|entry| entry.cache_hit));
}

#[test]
fn try_cache_wire_direct_returns_none_when_cached_resolution_has_no_wire_data() {
    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    let resolution = DnsResolutionBuilder::new()
        .with_address("1.2.3.4")
        .cache_hit()
        .build();
    resolver.set_cached_response("example.com", resolution);

    let use_case = make_use_case(resolver, filter, log);

    let result = use_case.try_cache_wire_direct(
        "example.com",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        served_wire,
    );

    assert!(result.is_none());
}

#[test]
fn try_cache_wire_direct_returns_none_when_domain_blocked() {
    use bytes::Bytes;
    use ferrous_dns_application::ports::EMPTY_CNAME_CHAIN;

    let resolver = Arc::new(MockDnsResolver::new());
    let filter = Arc::new(MockBlockFilterEngine::new());
    let log = Arc::new(MockQueryLogRepository::new());

    filter.block_domain("blocked.example.com");

    let resolution = DnsResolution {
        addresses: Arc::new(vec![]),
        cache_hit: true,
        local_dns: false,
        local_nxdomain: false,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: Some(60),
        negative_soa_ttl: None,
        upstream_wire_data: Some(Bytes::from_static(b"\xde\xad\xbe\xef")),
    };
    resolver.set_cached_response("blocked.example.com", resolution);

    let use_case = make_use_case(resolver, filter, log);

    let result = use_case.try_cache_wire_direct(
        "blocked.example.com",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        served_wire,
    );

    assert!(result.is_none());
}

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

//
// `resolve` expects callers to have probed the cache, so the rewrite must do
// it itself or every rewritten query goes upstream.

const SAFE_TARGET: &str = "forcesafesearch.google.com";

struct ForceSafeSearch;

#[async_trait]
impl SafeSearchEnginePort for ForceSafeSearch {
    fn cname_for(&self, domain: &str, _group_id: i64) -> Option<&'static str> {
        (domain == "www.google.com").then_some(SAFE_TARGET)
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Rewrites `www.google.com` with `cached` in the target's cache entry and
/// `resolved` as its upstream answer (unset: resolving fails the query).
async fn safe_search(
    cached: Option<DnsResolution>,
    resolved: Option<DnsResolution>,
) -> DnsResolution {
    let resolver = Arc::new(MockDnsResolver::new());
    if let Some(cached) = cached {
        resolver.set_cached_response(SAFE_TARGET, cached);
    }
    if let Some(resolved) = resolved {
        resolver.set_response(SAFE_TARGET, resolved).await;
    }
    let use_case = make_use_case(
        resolver,
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_safe_search(Arc::new(ForceSafeSearch));
    use_case
        .execute(&DnsRequest::new("www.google.com", RecordType::A, CLIENT_IP))
        .await
        .expect("rewrite answered")
}

#[tokio::test]
async fn test_safe_search_target_is_served_from_cache_without_resolving() {
    let result = safe_search(Some(cached_resolution("216.239.38.120")), None).await;
    assert!(result.cache_hit);
}

#[tokio::test]
async fn test_safe_search_target_resolves_on_a_miss_or_a_negative_entry() {
    let upstream = || Some(upstream_resolution("216.239.38.120"));
    assert!(!safe_search(None, upstream()).await.cache_hit);
    let negative = Some(DnsResolution::new(Vec::new(), true));
    assert!(!safe_search(negative, upstream()).await.cache_hit);
}
