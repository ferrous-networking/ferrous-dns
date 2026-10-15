//! The client's group travels with every query the use case hands the
//! resolver, so conditional pools routed for a group can answer it; and an
//! answer from an internal pool keeps the rebinding exemption local answers
//! have, live and from the cache.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, SafeSearchEnginePort};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{ClientProtocol, DnsRequest, DomainError, RecordType};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};

const GROUP: i64 = 7;
const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 42));
const OFFICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
const PUBLIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

fn use_case(resolver: Arc<MockDnsResolver>) -> HandleDnsQueryUseCase {
    let filter = MockBlockFilterEngine::new();
    filter.set_client_group(GROUP);
    HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(filter),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_rebinding_protection(None, &[])
}

fn internal_answer() -> DnsResolution {
    let mut resolution = DnsResolution::new(vec![OFFICE_IP], false);
    resolution.local_dns = true;
    resolution
}

#[tokio::test]
async fn test_execute_passes_the_client_group_to_the_cache_probe_and_resolution() {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver
        .set_response(
            "host.corp.example",
            DnsResolution::new(vec![PUBLIC_IP], false),
        )
        .await;
    let use_case = use_case(Arc::clone(&resolver));

    use_case
        .execute(&DnsRequest::new(
            "host.corp.example",
            RecordType::A,
            CLIENT_IP,
        ))
        .await
        .unwrap();

    assert_eq!(
        resolver.seen_groups(),
        [
            ("host.corp.example".to_string(), Some(GROUP)),
            ("host.corp.example".to_string(), Some(GROUP)),
        ]
    );
}

#[tokio::test]
async fn test_fast_path_cache_probes_pass_the_client_group() {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver.set_cached_response(
        "host.corp.example",
        DnsResolution::new(vec![PUBLIC_IP], true),
    );
    let use_case = use_case(Arc::clone(&resolver));

    let hit = use_case.try_cache_direct(
        "host.corp.example",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| Some(()),
    );
    assert!(hit.is_some());
    let _ = use_case.try_cache_wire_direct(
        "host.corp.example",
        RecordType::MX,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| Some(()),
    );

    assert_eq!(
        resolver.seen_groups(),
        [
            ("host.corp.example".to_string(), Some(GROUP)),
            ("host.corp.example".to_string(), Some(GROUP)),
        ]
    );
}

struct ForceSafeSearch;

#[async_trait]
impl SafeSearchEnginePort for ForceSafeSearch {
    fn cname_for(&self, domain: &str, _group_id: i64) -> Option<&'static str> {
        (domain == "www.google.com").then_some("forcesafesearch.google.com")
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_safe_search_rewrite_keeps_the_client_group() {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver
        .set_response(
            "forcesafesearch.google.com",
            DnsResolution::new(vec![IpAddr::V4(Ipv4Addr::new(216, 239, 38, 120))], false),
        )
        .await;
    let use_case = use_case(Arc::clone(&resolver)).with_safe_search(Arc::new(ForceSafeSearch));

    use_case
        .execute(&DnsRequest::new("www.google.com", RecordType::A, CLIENT_IP))
        .await
        .unwrap();

    assert!(resolver
        .seen_groups()
        .iter()
        .all(|(domain, group)| domain == "forcesafesearch.google.com" && *group == Some(GROUP)));
}

#[tokio::test]
async fn test_internal_answer_with_a_private_address_is_not_a_rebinding_attempt() {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver
        .set_response("host.corp.example", internal_answer())
        .await;
    let use_case = use_case(Arc::clone(&resolver));

    let result = use_case
        .execute(&DnsRequest::new(
            "host.corp.example",
            RecordType::A,
            CLIENT_IP,
        ))
        .await
        .unwrap();
    assert_eq!(*result.addresses, [OFFICE_IP]);
}

#[tokio::test]
async fn test_cached_internal_answer_with_a_private_address_is_served() {
    let resolver = Arc::new(MockDnsResolver::new());
    let mut cached = internal_answer();
    cached.cache_hit = true;
    resolver.set_cached_response("host.corp.example", cached);
    let use_case = use_case(Arc::clone(&resolver));

    let hit = use_case.try_cache_direct(
        "host.corp.example",
        RecordType::A,
        CLIENT_IP,
        ClientProtocol::Udp,
        |addresses, _| Some(addresses.to_vec()),
    );
    assert_eq!(hit, Some(vec![OFFICE_IP]));
}

#[tokio::test]
async fn test_same_private_answer_without_the_internal_mark_is_blocked() {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver
        .set_response(
            "host.corp.example",
            DnsResolution::new(vec![OFFICE_IP], false),
        )
        .await;
    let use_case = use_case(Arc::clone(&resolver));

    let result = use_case
        .execute(&DnsRequest::new(
            "host.corp.example",
            RecordType::A,
            CLIENT_IP,
        ))
        .await;
    assert!(matches!(result, Err(DomainError::Blocked)));
}
