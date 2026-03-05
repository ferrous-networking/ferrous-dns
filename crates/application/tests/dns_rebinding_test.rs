use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, DomainError, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};

fn make_use_case(
    resolver: MockDnsResolver,
    local_domain: Option<&str>,
    allowlist: &[String],
) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_rebinding_protection(true, local_domain, allowlist)
}

fn resolution_with_ip(ip: IpAddr) -> DnsResolution {
    DnsResolution::new(vec![ip], false)
}

fn resolution_with_ip_local_dns(ip: IpAddr) -> DnsResolution {
    let mut r = DnsResolution::new(vec![ip], false);
    r.local_dns = true;
    r
}

fn dns_request(domain: &str) -> DnsRequest {
    DnsRequest::new(domain, RecordType::A, "127.0.0.1".parse().unwrap())
}

#[tokio::test]
async fn test_public_domain_resolves_to_private_ip_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_public_domain_resolves_to_loopback_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_public_domain_resolves_to_link_local_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_public_domain_resolves_to_public_ip_is_allowed() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "google.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("google.com")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_local_domain_resolves_to_private_ip_is_allowed() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "server.local",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        )
        .await;

    let use_case = make_use_case(resolver, Some("local"), &[]);
    let result = use_case.execute(&dns_request("server.local")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_allowlisted_domain_resolves_to_private_ip_is_allowed() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "myrouter.corp",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        )
        .await;

    let allowlist = vec!["myrouter.corp".to_string()];
    let use_case = make_use_case(resolver, None, &allowlist);
    let result = use_case.execute(&dns_request("myrouter.corp")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_local_dns_resolution_is_exempt() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "internal.example",
            resolution_with_ip_local_dns(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 5))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("internal.example")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_public_domain_resolves_to_10_range_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_public_domain_resolves_to_172_16_range_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1))),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_public_domain_resolves_to_ipv6_loopback_is_blocked() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        )
        .await;

    let use_case = make_use_case(resolver, None, &[]);
    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(matches!(result, Err(DomainError::Blocked)));
}

#[tokio::test]
async fn test_local_domain_suffix_match_is_case_insensitive() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "Server.LOCAL",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        )
        .await;

    let use_case = make_use_case(resolver, Some("local"), &[]);
    let result = use_case.execute(&dns_request("Server.LOCAL")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_allowlist_match_is_case_insensitive() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "MyRouter.Corp",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        )
        .await;

    let allowlist = vec!["myrouter.corp".to_string()];
    let use_case = make_use_case(resolver, None, &allowlist);
    let result = use_case.execute(&dns_request("MyRouter.Corp")).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_protection_disabled_does_not_block() {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "evil.com",
            resolution_with_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        )
        .await;

    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_rebinding_protection(false, None, &[]);

    let result = use_case.execute(&dns_request("evil.com")).await;

    assert!(result.is_ok());
}
