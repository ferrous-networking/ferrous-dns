//! DNSSEC Strict-mode enforcement (RFC 4035 / 6840) at the use-case layer.
//!
//! Deterministic and network-free: the mock resolver returns a `DnsResolution`
//! pre-tagged with a `dnssec_status`, so we exercise the enforcement decision
//! without any real validation or upstream traffic.

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, DnssecStatus, DomainError, RecordType};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};

const PUBLIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

fn use_case(resolver: MockDnsResolver, enforce: bool) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_dnssec_enforcement(enforce)
}

async fn resolver_returning(status: Option<DnssecStatus>) -> MockDnsResolver {
    let mut resolution = DnsResolution::new(vec![PUBLIC_IP], false);
    resolution.dnssec_status = status;
    let resolver = MockDnsResolver::new();
    resolver.set_response("example.com", resolution).await;
    resolver
}

fn request(cd: bool) -> DnsRequest {
    DnsRequest::new("example.com", RecordType::A, "127.0.0.1".parse().unwrap())
        .with_checking_disabled(cd)
}

#[tokio::test]
async fn strict_mode_servfails_on_bogus() {
    let uc = use_case(resolver_returning(Some(DnssecStatus::Bogus)).await, true);
    let res = uc.execute(&request(false)).await;
    assert!(
        matches!(res, Err(DomainError::DnssecBogus)),
        "Strict mode must SERVFAIL on Bogus, got {res:?}"
    );
}

#[tokio::test]
async fn strict_mode_honors_cd_bit() {
    let uc = use_case(resolver_returning(Some(DnssecStatus::Bogus)).await, true);
    let res = uc.execute(&request(true)).await;
    assert!(res.is_ok(), "CD=1 must bypass enforcement, got {res:?}");
}

#[tokio::test]
async fn permissive_mode_serves_bogus() {
    let uc = use_case(resolver_returning(Some(DnssecStatus::Bogus)).await, false);
    let res = uc.execute(&request(false)).await;
    assert!(res.is_ok(), "Permissive must serve Bogus, got {res:?}");
}

#[tokio::test]
async fn strict_mode_servfails_on_indeterminate() {
    // A validation that could not complete (DS/DNSKEY lookups dropped or timed
    // out) is not a proof of insecurity; serving it would let anyone who can
    // drop those lookups switch validation off.
    let uc = use_case(
        resolver_returning(Some(DnssecStatus::Indeterminate)).await,
        true,
    );
    let res = uc.execute(&request(false)).await;
    assert!(
        matches!(res, Err(DomainError::DnssecIndeterminate)),
        "Strict mode must SERVFAIL on Indeterminate, got {res:?}"
    );
}

#[tokio::test]
async fn permissive_mode_serves_indeterminate() {
    let uc = use_case(
        resolver_returning(Some(DnssecStatus::Indeterminate)).await,
        false,
    );
    assert!(uc.execute(&request(false)).await.is_ok());
}

#[tokio::test]
async fn strict_mode_serves_proven_insecure() {
    let uc = use_case(resolver_returning(Some(DnssecStatus::Insecure)).await, true);
    assert!(uc.execute(&request(false)).await.is_ok());
}

#[tokio::test]
async fn strict_mode_fails_open_on_unknown() {
    let uc = use_case(resolver_returning(None).await, true);
    assert!(uc.execute(&request(false)).await.is_ok());
}

#[tokio::test]
async fn strict_mode_serves_secure() {
    let uc = use_case(resolver_returning(Some(DnssecStatus::Secure)).await, true);
    assert!(uc.execute(&request(false)).await.is_ok());
}
