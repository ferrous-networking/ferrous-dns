//! The resolver stack over conditional pools: an internal pool's answers are
//! trusted like the local DNS server's, a public one's are validated, and a
//! conditional pool beats `local_domain` and the private-range PTRs sent to
//! `local_dns_server`.

#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::{DnssecCache, TrustAnchorStore};
use ferrous_dns_infrastructure::dns::resolver::{NonFqdn, QueryFilters, ResolverBuilder};
use ferrous_dns_infrastructure::dns::PoolManager;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

const TIMEOUT_MS: u64 = 1_500;
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GOV_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const OFFICE_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const ROUTER_IP: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
const GROUP_A: i64 = 3;
const GROUP_B: i64 = 4;

struct Fixture {
    public: Upstream,
    gov: Upstream,
    office: Upstream,
    router: Upstream,
    pm: Arc<PoolManager>,
}

async fn fixture() -> Fixture {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let gov = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let office = Upstream::spawn(Answer::Address(OFFICE_IP)).await;
    let router = Upstream::spawn(Answer::Address(ROUTER_IP)).await;
    let pools = vec![
        UpstreamPool {
            name: "public".into(),
            strategy: UpstreamStrategy::Failover,
            servers: vec![public.url()],
            ..Default::default()
        },
        UpstreamPool {
            name: "gov".into(),
            strategy: UpstreamStrategy::Failover,
            servers: vec![gov.url()],
            domains: vec!["ru".into()],
            ..Default::default()
        },
        UpstreamPool {
            name: "office-a".into(),
            strategy: UpstreamStrategy::Failover,
            servers: vec![office.url()],
            domains: vec!["corp.example".into(), "1.10.in-addr.arpa".into()],
            groups: vec![GROUP_A],
            internal: true,
            ..Default::default()
        },
    ];
    let pm = Arc::new(PoolManager::new(pools, None).await.unwrap());
    Fixture {
        public,
        gov,
        office,
        router,
        pm,
    }
}

fn router_addr(router: &Upstream) -> SocketAddr {
    router.url().trim_start_matches("udp://").parse().unwrap()
}

/// The production stack with DNSSEC validation, `local_domain = corp.example`
/// and the router as `local_dns_server`.
fn stack(f: &Fixture) -> Arc<dyn DnsResolver> {
    ResolverBuilder::new(Arc::clone(&f.pm), TIMEOUT_MS)
        .with_dnssec(
            Arc::clone(&f.pm),
            TrustAnchorStore::new(),
            Arc::new(DnssecCache::new()),
        )
        .with_local_domain(Some("corp.example".into()))
        .with_local_dns_server(Some(router_addr(&f.router)))
        .build()
}

fn query(domain: &str, record_type: RecordType, group: i64) -> DnsQuery {
    DnsQuery::new(domain, record_type).with_group(Some(group))
}

#[tokio::test]
async fn test_internal_pool_answer_is_local_and_skips_dnssec_validation() {
    let f = fixture().await;
    let resolution = stack(&f)
        .resolve(&query("host.corp.example", RecordType::A, GROUP_A))
        .await
        .unwrap();
    assert_eq!(*resolution.addresses, [IpAddr::V4(OFFICE_IP)]);
    assert!(
        resolution.local_dns,
        "internal answers must be trusted like local ones"
    );
    assert_eq!(
        resolution.dnssec_status, None,
        "internal answers are never validated"
    );
    assert_eq!(resolution.upstream_pool.as_deref(), Some("office-a"));
    assert_eq!(f.router.queries(), 0);
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_public_routed_pool_answer_is_validated_without_leaking_to_default_pools() {
    let f = fixture().await;
    let resolution = stack(&f)
        .resolve(&query("example.ru", RecordType::A, GROUP_A))
        .await
        .unwrap();
    assert_eq!(*resolution.addresses, [IpAddr::V4(GOV_IP)]);
    assert!(!resolution.local_dns);
    assert!(
        resolution.dnssec_status.is_some(),
        "a public zone keeps DNSSEC validation"
    );
    assert!(
        f.public
            .asked()
            .iter()
            .all(|(name, _)| name != "ru." && !name.ends_with(".ru.")),
        "a name under the routed zone reached the default pool: {:?}",
        f.public.asked()
    );
}

#[tokio::test]
async fn test_group_route_beats_local_domain_and_other_groups_keep_the_router() {
    let f = fixture().await;
    let stack = stack(&f);

    let routed = stack
        .resolve(&query("nas.corp.example", RecordType::A, GROUP_A))
        .await
        .unwrap();
    assert_eq!(*routed.addresses, [IpAddr::V4(OFFICE_IP)]);
    assert_eq!(f.router.queries(), 0);

    let local = stack
        .resolve(&query("nas.corp.example", RecordType::A, GROUP_B))
        .await
        .unwrap();
    assert_eq!(*local.addresses, [IpAddr::V4(ROUTER_IP)]);
    assert!(local.local_dns);
    assert_eq!(f.router.queries(), 1);
}

#[tokio::test]
async fn test_routed_reverse_zone_beats_the_local_dns_server_for_private_ptrs() {
    let f = fixture().await;
    let stack = stack(&f);

    stack
        .resolve(&query("5.0.1.10.in-addr.arpa", RecordType::PTR, GROUP_A))
        .await
        .unwrap();
    assert_eq!(f.office.queries(), 1);
    assert_eq!(f.router.queries(), 0);

    // A private PTR outside the routed zone still goes to the router.
    stack
        .resolve(&query("5.0.2.10.in-addr.arpa", RecordType::PTR, GROUP_A))
        .await
        .unwrap();
    assert_eq!(f.router.queries(), 1);
    assert_eq!(f.office.queries(), 1);
}

#[tokio::test]
async fn test_dns64_synthesis_keeps_the_group_route_for_its_a_lookup() {
    let f = fixture().await;
    let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
    let stack = ResolverBuilder::new(Arc::clone(&f.pm), TIMEOUT_MS)
        .with_dns64(prefix)
        .build();

    let resolution = stack
        .resolve(&query("host.corp.example", RecordType::AAAA, GROUP_A))
        .await
        .unwrap();

    let synthesized: Ipv6Addr = "64:ff9b::c633:640a".parse().unwrap();
    assert_eq!(*resolution.addresses, [IpAddr::V6(synthesized)]);
    assert_eq!(
        f.office.queries(),
        2,
        "both the AAAA and the A must reach the office"
    );
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_unrouted_names_keep_their_existing_routes() {
    let f = fixture().await;
    let stack = stack(&f);

    let public = stack
        .resolve(&query("example.com", RecordType::A, GROUP_A))
        .await
        .unwrap();
    assert_eq!(*public.addresses, [IpAddr::V4(PUBLIC_IP)]);
    assert!(!public.local_dns);

    let lan = stack
        .resolve(&DnsQuery::new("printer.corp.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(*lan.addresses, [IpAddr::V4(ROUTER_IP)]);
    assert_eq!(f.gov.queries() + f.office.queries(), 0);
}

#[tokio::test]
async fn test_block_private_ptr_lets_a_routed_reverse_zone_through() {
    let f = fixture().await;
    // No local DNS server, so private PTRs are blocked as the wiring does it.
    let stack = ResolverBuilder::new(Arc::clone(&f.pm), TIMEOUT_MS)
        .with_filters(QueryFilters::new(true, NonFqdn::Pass))
        .build();

    stack
        .resolve(&query("5.0.1.10.in-addr.arpa", RecordType::PTR, GROUP_A))
        .await
        .expect("the office's reverse zone must reach its pool");
    assert_eq!(f.office.queries(), 1);

    for (name, group) in [
        ("5.0.2.10.in-addr.arpa", GROUP_A),
        ("5.0.1.10.in-addr.arpa", GROUP_B),
    ] {
        let result = stack.resolve(&query(name, RecordType::PTR, group)).await;
        assert!(
            matches!(result, Err(DomainError::FilteredQuery(_))),
            "{name} for group {group} must stay blocked: {result:?}"
        );
    }
    assert!(stack
        .try_cache_str("5.0.2.10.in-addr.arpa", RecordType::PTR, Some(GROUP_A))
        .is_none());
    assert_eq!(f.office.queries(), 1);
    assert_eq!(f.public.queries(), 0);
}
