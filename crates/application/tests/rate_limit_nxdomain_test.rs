mod helpers;

use bytes::Bytes;
use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{ClientProtocol, DnsRequest, DomainError, RateLimitConfig, RecordType};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const NX_PER_SECOND: u32 = 2;
/// NXDOMAIN burst capacity is twice the per-second budget.
const NX_BURST: u32 = NX_PER_SECOND * 2;

fn rate_limit(dry_run: bool, slip_ratio: u32) -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        queries_per_second: 1,
        burst_size: 1000,
        nxdomain_per_second: NX_PER_SECOND,
        slip_ratio,
        dry_run,
        ..RateLimitConfig::default()
    }
}

/// The resolver reports `Err(NxDomain)`, as it does for a local-TLD miss.
async fn use_case(config: RateLimitConfig) -> HandleDnsQueryUseCase {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response_error("nx.example.com", DomainError::NxDomain)
        .await;
    resolver
        .set_response(
            "ok.example.com",
            DnsResolution::new(vec!["192.0.2.1".parse().unwrap()], false),
        )
        .await;
    with_rate_limiter(resolver, config)
}

fn with_rate_limiter(resolver: MockDnsResolver, config: RateLimitConfig) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_rate_limiter(Arc::new(DnsRateLimiter::new(&config)))
}

/// An upstream's NXDOMAIN is relayed as the upstream's own message, so the
/// resolver returns it as a resolution without addresses, not as an error.
fn upstream_nxdomain(cache_hit: bool) -> DnsResolution {
    DnsResolution {
        upstream_nxdomain: true,
        upstream_wire_data: Some(Bytes::from_static(b"upstream NXDOMAIN")),
        min_ttl: Some(60),
        ..DnsResolution::new(vec![], cache_hit)
    }
}

/// The same answer from an internal pool, trusted like the local DNS server's.
fn internal_nxdomain(cache_hit: bool) -> DnsResolution {
    DnsResolution {
        local_dns: true,
        ..upstream_nxdomain(cache_hit)
    }
}

/// Fresh answers for `fresh.example.com`, cached ones for `cached.example.com`.
async fn resolver_answering(answer: fn(bool) -> DnsResolution) -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response("fresh.example.com", answer(false))
        .await;
    resolver.set_cached_response("cached.example.com", answer(true));
    resolver
}

/// What the UDP server does: the wire fast path first, `execute` when it declines.
async fn answer_over_udp(
    use_case: &HandleDnsQueryUseCase,
    domain: &str,
) -> Result<DnsResolution, DomainError> {
    let fast = use_case.try_cache_wire_direct(
        domain,
        RecordType::TXT,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| Some(()),
    );
    match fast {
        Some(()) => Ok(upstream_nxdomain(true)),
        None => {
            use_case
                .execute(&DnsRequest::new(domain, RecordType::TXT, CLIENT_IP))
                .await
        }
    }
}

fn request(domain: &str) -> DnsRequest {
    DnsRequest::new(domain, RecordType::A, CLIENT_IP)
}

#[tokio::test]
async fn only_nxdomain_answers_over_budget_are_rate_limited() {
    let use_case = use_case(rate_limit(false, 0)).await;

    for _ in 0..NX_BURST {
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::NxDomain)
        ));
    }

    for _ in 0..3 {
        // The spent budget does not refuse the client's resolving queries...
        assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
        // ...only its next NXDOMAIN answer.
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::DnsRateLimited)
        ));
    }
}

#[tokio::test]
async fn over_budget_nxdomain_answers_follow_the_slip_ratio() {
    let use_case = use_case(rate_limit(false, 2)).await;

    for _ in 0..NX_BURST {
        let _ = use_case.execute(&request("nx.example.com")).await;
    }

    assert!(matches!(
        use_case.execute(&request("nx.example.com")).await,
        Err(DomainError::DnsRateLimitedSlip)
    ));
    assert!(matches!(
        use_case.execute(&request("nx.example.com")).await,
        Err(DomainError::DnsRateLimited)
    ));
    assert!(use_case.execute(&request("ok.example.com")).await.is_ok());
}

#[tokio::test]
async fn dry_run_lets_nxdomain_answers_over_budget_through() {
    let use_case = use_case(rate_limit(true, 0)).await;

    for _ in 0..NX_BURST * 2 {
        assert!(matches!(
            use_case.execute(&request("nx.example.com")).await,
            Err(DomainError::NxDomain)
        ));
    }
}

#[tokio::test]
async fn fresh_upstream_nxdomain_answers_spend_the_nxdomain_budget() {
    let use_case = with_rate_limiter(
        resolver_answering(upstream_nxdomain).await,
        rate_limit(false, 0),
    );

    for _ in 0..NX_BURST {
        let answer = use_case.execute(&request("fresh.example.com")).await;
        assert!(answer.is_ok_and(|r| r.upstream_nxdomain));
    }

    assert!(matches!(
        use_case.execute(&request("fresh.example.com")).await,
        Err(DomainError::DnsRateLimited)
    ));
}

#[tokio::test]
async fn cached_upstream_nxdomain_answers_spend_the_nxdomain_budget() {
    let use_case = with_rate_limiter(
        resolver_answering(upstream_nxdomain).await,
        rate_limit(false, 0),
    );

    for _ in 0..NX_BURST {
        let answer = use_case.execute(&request("cached.example.com")).await;
        assert!(answer.is_ok_and(|r| r.upstream_nxdomain && r.cache_hit));
    }

    assert!(matches!(
        use_case.execute(&request("cached.example.com")).await,
        Err(DomainError::DnsRateLimited)
    ));
}

/// The wire fast path cannot charge the budget, so while the budget is on it
/// leaves a cached upstream NXDOMAIN to `execute`, which does.
#[tokio::test]
async fn fast_path_upstream_nxdomain_answers_spend_the_nxdomain_budget() {
    let use_case = with_rate_limiter(
        resolver_answering(upstream_nxdomain).await,
        rate_limit(false, 0),
    );

    for _ in 0..NX_BURST {
        assert!(answer_over_udp(&use_case, "cached.example.com")
            .await
            .is_ok());
    }

    assert!(matches!(
        answer_over_udp(&use_case, "cached.example.com").await,
        Err(DomainError::DnsRateLimited)
    ));
}

/// Guard: with no NXDOMAIN budget the fast path keeps answering them.
#[tokio::test]
async fn fast_path_answers_upstream_nxdomains_when_there_is_no_budget() {
    let config = RateLimitConfig {
        nxdomain_per_second: 0,
        ..rate_limit(false, 0)
    };
    let use_case = with_rate_limiter(resolver_answering(upstream_nxdomain).await, config);

    let fast = use_case.try_cache_wire_direct(
        "cached.example.com",
        RecordType::TXT,
        CLIENT_IP,
        ClientProtocol::Udp,
        |_, _| Some(()),
    );

    assert!(fast.is_some());
}

/// Guard: an internal pool's NXDOMAINs are the LAN's own, like the local DNS
/// server's, and never spend the budget — fresh, cached or on the fast path.
#[tokio::test]
async fn internal_pool_nxdomain_answers_are_never_charged() {
    let use_case = with_rate_limiter(
        resolver_answering(internal_nxdomain).await,
        rate_limit(false, 0),
    );

    for _ in 0..NX_BURST * 2 {
        assert!(use_case
            .execute(&request("fresh.example.com"))
            .await
            .is_ok());
        assert!(use_case
            .execute(&request("cached.example.com"))
            .await
            .is_ok());
        assert!(use_case
            .try_cache_wire_direct(
                "cached.example.com",
                RecordType::TXT,
                CLIENT_IP,
                ClientProtocol::Udp,
                |_, _| Some(()),
            )
            .is_some());
    }
}
