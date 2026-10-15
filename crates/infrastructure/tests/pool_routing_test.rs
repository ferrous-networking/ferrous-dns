//! Conditional pools: a pool with `domains` answers those domains (for every
//! client or for its `groups`) and nothing else, and a routed name is never
//! asked anywhere else.

#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_domain::{DomainError, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::load_balancer::{PoolManager, Route, UpstreamRouter};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

const TIMEOUT_MS: u64 = 1_500;
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GOV_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const OFFICE_A_IP: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 1);
const OFFICE_B_IP: Ipv4Addr = Ipv4Addr::new(10, 2, 2, 2);
const GROUP_A: i64 = 3;
const GROUP_B: i64 = 4;

fn default_pool(name: &str, priority: u8, upstream: &Upstream) -> UpstreamPool {
    UpstreamPool {
        name: name.to_string(),
        strategy: UpstreamStrategy::Failover,
        priority,
        servers: vec![upstream.url()],
        ..Default::default()
    }
}

fn conditional_pool(
    name: &str,
    upstream: &Upstream,
    domains: &[&str],
    groups: &[i64],
    internal: bool,
) -> UpstreamPool {
    UpstreamPool {
        name: name.to_string(),
        strategy: UpstreamStrategy::Failover,
        servers: vec![upstream.url()],
        domains: domains.iter().map(|d| d.to_string()).collect(),
        groups: groups.to_vec(),
        internal,
        ..Default::default()
    }
}

async fn manager(pools: Vec<UpstreamPool>) -> PoolManager {
    PoolManager::new(pools, None).await.unwrap()
}

async fn resolve(
    pm: &PoolManager,
    group: Option<i64>,
    domain: &str,
) -> Result<(Vec<IpAddr>, Arc<str>), DomainError> {
    let domain: Arc<str> = Arc::from(domain);
    let result = pm
        .query_for(group, &domain, &RecordType::A, TIMEOUT_MS, true)
        .await?;
    Ok((result.response.addresses, result.pool_name))
}

async fn resolve_ip(pm: &PoolManager, group: Option<i64>, domain: &str) -> IpAddr {
    resolve(pm, group, domain)
        .await
        .unwrap_or_else(|e| panic!("{domain} for {group:?} must resolve: {e}"))
        .0[0]
}

struct Fixture {
    public: Upstream,
    gov: Upstream,
    office_a: Upstream,
    office_b: Upstream,
    pm: PoolManager,
}

/// The reporter's setup from issue #272: a national zone for everyone and a
/// corporate zone answered by each office's server.
async fn fixture() -> Fixture {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let gov = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let office_a = Upstream::spawn(Answer::Address(OFFICE_A_IP)).await;
    let office_b = Upstream::spawn(Answer::Address(OFFICE_B_IP)).await;
    let pm = manager(vec![
        default_pool("public", 1, &public),
        conditional_pool("gov", &gov, &["ru", "рф"], &[], false),
        conditional_pool("office-a", &office_a, &["corp.example"], &[GROUP_A], true),
        conditional_pool("office-b", &office_b, &["corp.example"], &[GROUP_B], true),
    ])
    .await;
    Fixture {
        public,
        gov,
        office_a,
        office_b,
        pm,
    }
}

#[tokio::test]
async fn test_unrouted_name_uses_the_default_pools_only() {
    let f = fixture().await;
    assert_eq!(resolve_ip(&f.pm, None, "example.com").await, PUBLIC_IP);
    assert_eq!(
        resolve_ip(&f.pm, Some(GROUP_A), "example.com").await,
        PUBLIC_IP
    );
    assert_eq!(
        f.gov.queries() + f.office_a.queries() + f.office_b.queries(),
        0
    );
}

#[tokio::test]
async fn test_routed_domain_and_every_name_under_it_go_to_its_pool() {
    let f = fixture().await;
    for name in [
        "ru",
        "example.ru",
        "a.b.example.ru",
        "EXAMPLE.RU",
        "example.ru.",
    ] {
        let (addrs, pool) = resolve(&f.pm, None, name).await.unwrap();
        assert_eq!(addrs, [IpAddr::V4(GOV_IP)], "{name}");
        assert_eq!(&*pool, "gov", "{name}");
    }
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_unicode_domain_matches_its_punycode_query_name() {
    let f = fixture().await;
    assert_eq!(
        resolve_ip(&f.pm, None, "xn--e1afmkfd.xn--p1ai").await,
        GOV_IP
    );
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_a_name_that_only_ends_like_a_routed_domain_is_not_routed() {
    let f = fixture().await;
    assert_eq!(resolve_ip(&f.pm, None, "guru").await, PUBLIC_IP);
    assert_eq!(resolve_ip(&f.pm, None, "notcorp.example").await, PUBLIC_IP);
    assert_eq!(f.gov.queries() + f.office_a.queries(), 0);
}

#[tokio::test]
async fn test_group_route_answers_only_its_group() {
    let f = fixture().await;
    assert_eq!(
        resolve_ip(&f.pm, Some(GROUP_A), "host.corp.example").await,
        OFFICE_A_IP
    );
    assert_eq!(
        resolve_ip(&f.pm, Some(GROUP_B), "host.corp.example").await,
        OFFICE_B_IP
    );
    // Neither a client outside both groups nor the group-less chain walk sees them.
    assert_eq!(
        resolve_ip(&f.pm, Some(99), "host.corp.example").await,
        PUBLIC_IP
    );
    assert_eq!(
        resolve_ip(&f.pm, None, "host.corp.example").await,
        PUBLIC_IP
    );
}

#[tokio::test]
async fn test_group_route_wins_over_every_client_route_for_the_same_domain() {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let shared = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let office = Upstream::spawn(Answer::Address(OFFICE_A_IP)).await;
    let pm = manager(vec![
        default_pool("public", 1, &public),
        conditional_pool("shared", &shared, &["corp.example"], &[], true),
        conditional_pool("office", &office, &["corp.example"], &[GROUP_A], true),
    ])
    .await;
    assert_eq!(
        resolve_ip(&pm, Some(GROUP_A), "corp.example").await,
        OFFICE_A_IP
    );
    assert_eq!(resolve_ip(&pm, Some(GROUP_B), "corp.example").await, GOV_IP);
    assert_eq!(resolve_ip(&pm, None, "corp.example").await, GOV_IP);
}

#[tokio::test]
async fn test_most_specific_domain_wins() {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let broad = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let narrow = Upstream::spawn(Answer::Address(OFFICE_A_IP)).await;
    let pm = manager(vec![
        default_pool("public", 1, &public),
        conditional_pool("broad", &broad, &["example"], &[GROUP_A], false),
        conditional_pool("narrow", &narrow, &["corp.example"], &[], false),
    ])
    .await;
    // The every-client route for the longer domain beats the group's shorter one.
    assert_eq!(
        resolve_ip(&pm, Some(GROUP_A), "a.corp.example").await,
        OFFICE_A_IP
    );
    assert_eq!(
        resolve_ip(&pm, Some(GROUP_A), "a.other.example").await,
        GOV_IP
    );
}

#[tokio::test]
async fn test_a_domain_only_another_group_routes_falls_back_to_the_parent_route() {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let parent = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let office = Upstream::spawn(Answer::Address(OFFICE_A_IP)).await;
    let pm = manager(vec![
        default_pool("public", 1, &public),
        conditional_pool("parent", &parent, &["example"], &[], false),
        conditional_pool("office", &office, &["corp.example"], &[GROUP_A], true),
    ])
    .await;
    assert_eq!(
        resolve_ip(&pm, Some(GROUP_B), "a.corp.example").await,
        GOV_IP
    );
}

#[tokio::test]
async fn test_routed_pool_failure_is_never_retried_on_the_default_pools() {
    let f = fixture().await;
    f.gov.set(Answer::Silent);
    let result = resolve(&f.pm, None, "example.ru").await;
    assert!(
        result.is_err(),
        "a down routed pool must fail the query: {result:?}"
    );
    assert_eq!(
        f.public.queries(),
        0,
        "the routed name leaked to the default pool"
    );
}

#[tokio::test]
async fn test_routed_pool_nxdomain_is_the_answer() {
    let f = fixture().await;
    f.office_a.set(Answer::NxDomain);
    let domain: Arc<str> = Arc::from("missing.corp.example");
    let result =
        f.pm.query_for(Some(GROUP_A), &domain, &RecordType::A, TIMEOUT_MS, false)
            .await
            .unwrap();
    assert!(result.response.is_nxdomain());
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_default_walk_never_asks_a_conditional_pool() {
    let primary = Upstream::spawn(Answer::Silent).await;
    let routed = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let fallback = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    // The conditional pool has the best priority, yet it is not a fallback.
    let mut gov = conditional_pool("gov", &routed, &["ru"], &[], false);
    gov.priority = 0;
    let pm = manager(vec![
        default_pool("primary", 1, &primary),
        gov,
        default_pool("fallback", 2, &fallback),
    ])
    .await;
    assert_eq!(resolve_ip(&pm, None, "example.com").await, PUBLIC_IP);
    assert_eq!(routed.queries(), 0);
}

#[tokio::test]
async fn test_internal_pool_is_asked_without_the_do_bit_and_reports_internal() {
    let f = fixture().await;
    let domain: Arc<str> = Arc::from("host.corp.example");
    let result =
        f.pm.query_for(Some(GROUP_A), &domain, &RecordType::A, TIMEOUT_MS, true)
            .await
            .unwrap();
    assert!(result.internal);
    assert!(!f.office_a.last_dnssec_ok());
}

#[tokio::test]
async fn test_public_routed_pool_keeps_the_do_bit_and_is_not_internal() {
    let f = fixture().await;
    let domain: Arc<str> = Arc::from("example.ru");
    let result =
        f.pm.query_for(None, &domain, &RecordType::A, TIMEOUT_MS, true)
            .await
            .unwrap();
    assert!(!result.internal);
    assert!(f.gov.last_dnssec_ok());
}

#[tokio::test]
async fn test_chain_walk_query_follows_every_client_routes() {
    let f = fixture().await;
    let domain: Arc<str> = Arc::from("example.ru");
    f.pm.query(&domain, &RecordType::DNSKEY, TIMEOUT_MS, true)
        .await
        .unwrap();
    assert_eq!(
        f.gov.asked(),
        [(
            "example.ru.".to_string(),
            hickory_proto::rr::RecordType::DNSKEY
        )]
    );
    assert_eq!(f.public.queries(), 0);
}

#[tokio::test]
async fn test_router_reports_routes_and_views() {
    let f = fixture().await;
    assert_eq!(f.pm.route("example.com", Some(GROUP_A)), None);
    assert_eq!(
        f.pm.route("x.ru", Some(GROUP_A)),
        Some(Route {
            view: 0,
            internal: false
        })
    );
    assert_eq!(
        f.pm.route("x.corp.example", Some(GROUP_B)),
        Some(Route {
            view: GROUP_B as u32,
            internal: true
        })
    );
    assert_eq!(f.pm.view("x.corp.example", Some(GROUP_A)), GROUP_A as u32);
    assert_eq!(f.pm.view("x.corp.example", Some(99)), 0);
    assert_eq!(f.pm.view("x.corp.example", None), 0);
    assert_eq!(f.pm.view("x.ru", Some(GROUP_A)), 0);
}

#[tokio::test]
async fn test_reload_swaps_routes_with_the_pools() {
    let f = fixture().await;
    assert_eq!(resolve_ip(&f.pm, None, "example.ru").await, GOV_IP);
    f.pm.reload(vec![default_pool("public", 1, &f.public)])
        .await
        .unwrap();
    assert_eq!(resolve_ip(&f.pm, None, "example.ru").await, PUBLIC_IP);
    assert_eq!(f.pm.route("x.corp.example", Some(GROUP_A)), None);
}

#[tokio::test]
async fn test_only_conditional_pools_is_rejected() {
    let gov = Upstream::spawn(Answer::Address(GOV_IP)).await;
    let result = PoolManager::new(
        vec![conditional_pool("gov", &gov, &["ru"], &[], false)],
        None,
    )
    .await;
    assert!(matches!(result, Err(DomainError::ConfigError(_))));
}
