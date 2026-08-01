//! An explicit allow must clear a false positive from every heuristic detector.
//!
//! The five detectors the dashboard aggregates as "Malware detection" — DNS
//! tunneling, DGA, rebinding, NXDOMAIN hijack and response-IP filtering — used
//! to run either side of the block filter without ever consulting the allowlist,
//! so a domain the operator had explicitly allowed stayed blocked with no way
//! out short of editing the TOML and restarting.
//!
//! Every test here runs the same query twice against the same fully wired
//! pipeline: once without the allow (the detector must still fire, otherwise the
//! second half would prove nothing) and once with it.

mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    DgaDetectionAction, DgaDetectionConfig, DnsRequest, DomainError, NxdomainHijackAction,
    NxdomainHijackConfig, RecordType, ResponseIpFilterAction, ResponseIpFilterConfig,
    TunnelingAction, TunnelingDetectionConfig,
};
use helpers::{
    MockBlockFilterEngine, MockDgaFlagStore, MockDnsResolver, MockNxdomainHijackIpStore,
    MockQueryLogRepository, MockResponseIpFilterStore, MockTunnelingFlagStore,
};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

/// Trips the DGA guard's hot-path scoring on its own.
const DGA_SHAPED: &str = "xjk4f9a2h3b5c7d.com";
const TUNNELING_FLAGGED: &str = "tunnel-flagged.example.com";
const DGA_FLAGGED: &str = "dga-flagged.example.com";
const REBINDING: &str = "rebind.example.com";
const HIJACKED: &str = "hijack.example.com";
const C2: &str = "c2.example.com";

const PRIVATE_IP: &str = "192.168.1.5";
const HIJACK_IP: &str = "203.0.113.99";
const C2_IP: &str = "198.51.100.7";

/// Everything the wired pipeline needs to make exactly one detector fire.
#[derive(Default)]
struct Fixture {
    hijack_ip: Option<&'static str>,
    c2_ip: Option<&'static str>,
    tunneling_flagged: Option<&'static str>,
    dga_flagged: Option<&'static str>,
    /// The domain to mark as explicitly allowed, i.e. what the operator would
    /// add to clear the false positive.
    allowed: Option<&'static str>,
}

/// Builds a use case with all five detectors enabled and set to block, so each
/// test exercises the exemption against the real ordering rather than against a
/// pipeline trimmed down to the detector under test.
fn build(resolver: MockDnsResolver, fixture: Fixture) -> HandleDnsQueryUseCase {
    let block_filter = MockBlockFilterEngine::new();
    if let Some(domain) = fixture.allowed {
        block_filter.allow_domain(domain);
    }

    let hijack_store = Arc::new(MockNxdomainHijackIpStore::new());
    if let Some(ip) = fixture.hijack_ip {
        hijack_store.add_hijack_ip(ip.parse().unwrap());
    }

    let c2_store = Arc::new(MockResponseIpFilterStore::new());
    if let Some(ip) = fixture.c2_ip {
        c2_store.add_blocked_ip(ip.parse().unwrap());
    }

    let tunneling_store = Arc::new(MockTunnelingFlagStore::new());
    if let Some(domain) = fixture.tunneling_flagged {
        tunneling_store.flag_domain(domain);
    }

    let dga_store = Arc::new(MockDgaFlagStore::new());
    if let Some(domain) = fixture.dga_flagged {
        dga_store.flag_domain(domain);
    }

    let tunneling_config = TunnelingDetectionConfig {
        enabled: true,
        action: TunnelingAction::Block,
        max_fqdn_length: 120,
        max_label_length: 50,
        block_null_queries: true,
        ..Default::default()
    };
    let dga_config = DgaDetectionConfig {
        enabled: true,
        action: DgaDetectionAction::Block,
        ..Default::default()
    };
    let hijack_config = NxdomainHijackConfig {
        enabled: true,
        action: NxdomainHijackAction::Block,
        ..Default::default()
    };
    let c2_config = ResponseIpFilterConfig {
        enabled: true,
        action: ResponseIpFilterAction::Block,
        ..Default::default()
    };

    HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(block_filter),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_tunneling_detection(&tunneling_config)
    .with_tunneling_flag_store(tunneling_store)
    .with_dga_detection(&dga_config)
    .with_dga_flag_store(dga_store)
    .with_rebinding_protection(true, None, &[])
    .with_nxdomain_hijack_detection(&hijack_config, hijack_store)
    .with_response_ip_filter(&c2_config, c2_store)
}

async fn resolver_with_ip(domain: &str, ip: &str) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(domain, DnsResolution::new(vec![ip.parse().unwrap()], false))
        .await;
    resolver
}

// ── DGA ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_allow_clears_a_dga_false_positive() {
    let control = build(
        resolver_with_ip(DGA_SHAPED, "1.2.3.4").await,
        Fixture::default(),
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(DGA_SHAPED, RecordType::A, CLIENT_IP))
                .await,
            Err(DomainError::DgaDomainDetected)
        ),
        "control: the DGA guard must fire on this domain, or the allow below proves nothing"
    );

    let allowed = build(
        resolver_with_ip(DGA_SHAPED, "1.2.3.4").await,
        Fixture {
            allowed: Some(DGA_SHAPED),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(DGA_SHAPED, RecordType::A, CLIENT_IP))
            .await
            .is_ok(),
        "an explicitly allowed domain must not be blocked by DGA detection"
    );
}

#[tokio::test]
async fn explicit_allow_clears_a_background_dga_flag() {
    let control = build(
        resolver_with_ip(DGA_FLAGGED, "1.2.3.4").await,
        Fixture {
            dga_flagged: Some(DGA_FLAGGED),
            ..Default::default()
        },
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(DGA_FLAGGED, RecordType::A, CLIENT_IP))
                .await,
            Err(DomainError::DgaDomainDetected)
        ),
        "control: a flagged domain must be blocked"
    );

    let allowed = build(
        resolver_with_ip(DGA_FLAGGED, "1.2.3.4").await,
        Fixture {
            dga_flagged: Some(DGA_FLAGGED),
            allowed: Some(DGA_FLAGGED),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(DGA_FLAGGED, RecordType::A, CLIENT_IP))
            .await
            .is_ok(),
        "an explicit allow must also clear a domain flagged by the phase-2 analyzer"
    );
}

// ── Tunneling ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_allow_clears_a_tunneling_false_positive() {
    // A NULL query is what the phase-1 guard keys on here.
    let control = build(
        resolver_with_ip(HIJACKED, "1.2.3.4").await,
        Fixture::default(),
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(HIJACKED, RecordType::NULL, CLIENT_IP))
                .await,
            Err(DomainError::DnsTunnelingDetected)
        ),
        "control: a NULL query must trip the tunneling guard"
    );

    let allowed = build(
        resolver_with_ip(HIJACKED, "1.2.3.4").await,
        Fixture {
            allowed: Some(HIJACKED),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(HIJACKED, RecordType::NULL, CLIENT_IP))
            .await
            .is_ok(),
        "an explicitly allowed domain must not be blocked by tunneling detection"
    );
}

#[tokio::test]
async fn explicit_allow_clears_a_background_tunneling_flag() {
    let control = build(
        resolver_with_ip(TUNNELING_FLAGGED, "1.2.3.4").await,
        Fixture {
            tunneling_flagged: Some(TUNNELING_FLAGGED),
            ..Default::default()
        },
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(
                    TUNNELING_FLAGGED,
                    RecordType::A,
                    CLIENT_IP
                ))
                .await,
            Err(DomainError::DnsTunnelingDetected)
        ),
        "control: a flagged domain must be blocked"
    );

    let allowed = build(
        resolver_with_ip(TUNNELING_FLAGGED, "1.2.3.4").await,
        Fixture {
            tunneling_flagged: Some(TUNNELING_FLAGGED),
            allowed: Some(TUNNELING_FLAGGED),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(
                TUNNELING_FLAGGED,
                RecordType::A,
                CLIENT_IP
            ))
            .await
            .is_ok(),
        "an explicit allow must also clear a domain flagged by the phase-2 analyzer"
    );
}

// ── Rebinding ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_allow_clears_a_rebinding_false_positive() {
    let control = build(
        resolver_with_ip(REBINDING, PRIVATE_IP).await,
        Fixture::default(),
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(REBINDING, RecordType::A, CLIENT_IP))
                .await,
            Err(DomainError::Blocked)
        ),
        "control: a public name resolving to a private IP must be blocked"
    );

    let allowed = build(
        resolver_with_ip(REBINDING, PRIVATE_IP).await,
        Fixture {
            allowed: Some(REBINDING),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(REBINDING, RecordType::A, CLIENT_IP))
            .await
            .is_ok(),
        "an explicitly allowed domain must not be blocked by rebinding protection"
    );
}

// ── NXDOMAIN hijack ──────────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_allow_clears_an_nxdomain_hijack_false_positive() {
    let control = build(
        resolver_with_ip(HIJACKED, HIJACK_IP).await,
        Fixture {
            hijack_ip: Some(HIJACK_IP),
            ..Default::default()
        },
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(HIJACKED, RecordType::A, CLIENT_IP))
                .await,
            Err(DomainError::NxDomain)
        ),
        "control: a response carrying a known hijack IP must be blocked"
    );

    let allowed = build(
        resolver_with_ip(HIJACKED, HIJACK_IP).await,
        Fixture {
            hijack_ip: Some(HIJACK_IP),
            allowed: Some(HIJACKED),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(HIJACKED, RecordType::A, CLIENT_IP))
            .await
            .is_ok(),
        "an explicitly allowed domain must not be blocked by NXDOMAIN hijack detection"
    );
}

// ── Response IP filter ───────────────────────────────────────────────────────

#[tokio::test]
async fn explicit_allow_clears_a_response_ip_false_positive() {
    let control = build(
        resolver_with_ip(C2, C2_IP).await,
        Fixture {
            c2_ip: Some(C2_IP),
            ..Default::default()
        },
    );
    assert!(
        matches!(
            control
                .execute(&DnsRequest::new(C2, RecordType::A, CLIENT_IP))
                .await,
            Err(DomainError::Blocked)
        ),
        "control: a response carrying a known C2 IP must be blocked"
    );

    let allowed = build(
        resolver_with_ip(C2, C2_IP).await,
        Fixture {
            c2_ip: Some(C2_IP),
            allowed: Some(C2),
            ..Default::default()
        },
    );
    assert!(
        allowed
            .execute(&DnsRequest::new(C2, RecordType::A, CLIENT_IP))
            .await
            .is_ok(),
        "an explicitly allowed domain must not be blocked by the response IP filter"
    );
}

/// The cached fast path repeats every one of these checks, so it needs the same
/// exemption — otherwise the verdict would flip depending on whether the answer
/// happened to be in the cache.
#[tokio::test]
async fn explicit_allow_survives_the_cached_path() {
    let resolver = MockDnsResolver::new();
    let c2_ip: IpAddr = C2_IP.parse().unwrap();
    resolver.set_cached_response(C2, DnsResolution::new(vec![c2_ip], true));
    resolver
        .set_response(C2, DnsResolution::new(vec![c2_ip], false))
        .await;

    let allowed = build(
        resolver,
        Fixture {
            c2_ip: Some(C2_IP),
            allowed: Some(C2),
            ..Default::default()
        },
    );

    let result = allowed
        .execute(&DnsRequest::new(C2, RecordType::A, CLIENT_IP))
        .await;

    assert!(
        result.is_ok(),
        "a cached answer for an explicitly allowed domain must be served, not \
         re-resolved and blocked"
    );
    assert!(
        result.unwrap().cache_hit,
        "the cached answer must be served from the cache rather than falling \
         through to the resolver"
    );
}
