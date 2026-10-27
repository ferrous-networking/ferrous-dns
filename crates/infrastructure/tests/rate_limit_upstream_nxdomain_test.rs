//! The NXDOMAIN budget (`nxdomain_per_second`) is charged for each NXDOMAIN a
//! client is answered with. An upstream's NXDOMAIN is relayed as the
//! upstream's own message, so the resolver hands it back as a resolution, not
//! an error, and the budget must still see it: fresh, from the cache, and when
//! the UDP fast path holds it. An internal pool's NXDOMAINs are the LAN's own,
//! like the local DNS server's, and are never charged.

#[path = "support/ports.rs"]
mod ports;
#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::{DnsResolution, QueryLogRepository};
use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    ClientProtocol, DnsRequest, DomainError, RateLimitConfig, RecordType, UpstreamPool,
    UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
use ferrous_dns_infrastructure::dns::PoolManager;
use ports::{AllowAllFilter, RecordingQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const TIMEOUT_MS: u64 = 2_000;
const NX_PER_SECOND: u32 = 2;
/// NXDOMAIN burst capacity is twice the per-second budget.
const NX_BURST: u32 = NX_PER_SECOND * 2;
const INTERNAL_ZONE: &str = "corp.example";

struct Fixture {
    public: Upstream,
    _office: Upstream,
    use_case: HandleDnsQueryUseCase,
}

/// The use case over the server's resolver stack and cache, with the
/// NXDOMAIN budget on: a public pool, and an internal pool for
/// `corp.example`, both answering NXDOMAIN to every name.
async fn fixture() -> Fixture {
    let public = Upstream::spawn(Answer::NxDomain).await;
    let office = Upstream::spawn(Answer::NxDomain).await;
    let pools = vec![
        UpstreamPool {
            name: "public".into(),
            strategy: UpstreamStrategy::Failover,
            servers: vec![public.url()],
            ..Default::default()
        },
        UpstreamPool {
            name: "office".into(),
            strategy: UpstreamStrategy::Failover,
            servers: vec![office.url()],
            domains: vec![INTERNAL_ZONE.into()],
            internal: true,
            ..Default::default()
        },
    ];
    let pm = Arc::new(PoolManager::new(pools, None).await.unwrap());
    let cache = refresh::refresh_cache(1_000, 0.75, 7_200);
    let stack = ResolverBuilder::new(pm, TIMEOUT_MS)
        .with_cache(cache, 7_200, 4)
        .build();
    let use_case = HandleDnsQueryUseCase::new(
        stack,
        Arc::new(AllowAllFilter),
        Arc::new(RecordingQueryLog::default()) as Arc<dyn QueryLogRepository>,
    )
    .with_rate_limiter(Arc::new(DnsRateLimiter::new(&RateLimitConfig {
        enabled: true,
        queries_per_second: 1,
        burst_size: 1_000,
        nxdomain_per_second: NX_PER_SECOND,
        ..RateLimitConfig::default()
    })));
    Fixture {
        public,
        _office: office,
        use_case,
    }
}

async fn execute(
    use_case: &HandleDnsQueryUseCase,
    domain: &str,
    record_type: RecordType,
) -> Result<DnsResolution, DomainError> {
    use_case
        .execute(&DnsRequest::new(domain, record_type, CLIENT))
        .await
}

/// Whether the UDP fast path answers `domain`'s cached TXT itself.
fn fast_path_answers(use_case: &HandleDnsQueryUseCase, domain: &str) -> bool {
    use_case
        .try_cache_wire_direct(
            domain,
            RecordType::TXT,
            CLIENT,
            ClientProtocol::Udp,
            |_, _| Some(()),
        )
        .is_some()
}

fn is_nxdomain_answer(answer: &Result<DnsResolution, DomainError>) -> bool {
    answer.as_ref().is_ok_and(|r| r.upstream_nxdomain)
}

/// A random-subdomain flood: every name is new, so every answer is fresh.
#[tokio::test]
async fn fresh_upstream_nxdomains_spend_the_budget() {
    let f = fixture().await;

    for i in 0..NX_BURST {
        let answer = execute(&f.use_case, &format!("r{i}.gone.example"), RecordType::A).await;
        assert!(is_nxdomain_answer(&answer), "query {i}: {answer:?}");
    }

    let over = execute(&f.use_case, "over.gone.example", RecordType::A).await;
    assert!(
        matches!(over, Err(DomainError::DnsRateLimited)),
        "the NXDOMAIN over the budget must be refused, got {over:?}"
    );
}

#[tokio::test]
async fn cached_upstream_nxdomains_spend_the_budget() {
    let f = fixture().await;

    for i in 0..NX_BURST {
        let answer = execute(&f.use_case, "gone.example", RecordType::A).await;
        assert!(is_nxdomain_answer(&answer), "query {i}: {answer:?}");
    }
    assert_eq!(
        f.public.queries(),
        1,
        "every query after the first is a cache hit"
    );

    let over = execute(&f.use_case, "gone.example", RecordType::A).await;
    assert!(
        matches!(over, Err(DomainError::DnsRateLimited)),
        "the cached NXDOMAIN over the budget must be refused, got {over:?}"
    );
}

/// The fast path cannot charge the budget, so it must leave the query to
/// `execute`, which does.
#[tokio::test]
async fn fast_path_leaves_cached_upstream_nxdomains_to_the_budget() {
    let f = fixture().await;
    let first = execute(&f.use_case, "gone.example", RecordType::TXT).await;
    assert!(is_nxdomain_answer(&first));

    assert!(
        !fast_path_answers(&f.use_case, "gone.example"),
        "the fast path must not answer an NXDOMAIN while the budget is on"
    );
    for _ in 1..NX_BURST {
        let answer = execute(&f.use_case, "gone.example", RecordType::TXT).await;
        assert!(is_nxdomain_answer(&answer));
    }
    let over = execute(&f.use_case, "gone.example", RecordType::TXT).await;
    assert!(
        matches!(over, Err(DomainError::DnsRateLimited)),
        "got {over:?}"
    );
}

/// Guard: the LAN's own NXDOMAINs never spend the budget.
#[tokio::test]
async fn internal_pool_nxdomains_are_never_charged() {
    let f = fixture().await;

    for i in 0..NX_BURST * 2 {
        let fresh = execute(&f.use_case, &format!("h{i}.{INTERNAL_ZONE}"), RecordType::A).await;
        assert!(is_nxdomain_answer(&fresh), "fresh {i}: {fresh:?}");
        let cached = execute(
            &f.use_case,
            &format!("printer.{INTERNAL_ZONE}"),
            RecordType::TXT,
        )
        .await;
        assert!(is_nxdomain_answer(&cached), "cached {i}: {cached:?}");
    }
    assert!(fast_path_answers(
        &f.use_case,
        &format!("printer.{INTERNAL_ZONE}")
    ));
}
