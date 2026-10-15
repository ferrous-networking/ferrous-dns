//! Split-horizon answers are cached per client group. A name a group routes
//! to its own pool is stored in that group's view of the cache, so one group
//! never receives another group's answer; every other name stays in the one
//! view all clients share.

#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
use ferrous_dns_infrastructure::dns::{DnsCache, PoolManager};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use upstream::{Answer, Upstream};

const TIMEOUT_MS: u64 = 1_500;
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const OFFICE_A_IP: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 1);
const OFFICE_B_IP: Ipv4Addr = Ipv4Addr::new(10, 2, 2, 2);
const LOCAL_IP: &str = "10.0.0.5";
const GROUP_A: i64 = 3;
const GROUP_B: i64 = 4;
const OTHER_GROUP: i64 = 99;
const NAME: &str = "host.corp.example";
/// The response parser keeps the target's trailing dot, so the cache stores a
/// chain target under that form; check both.
const TARGET_FORMS: [&str; 2] = ["lb.cdn.example", "lb.cdn.example."];

fn pool(name: &str, upstream: &Upstream, domains: &[&str], groups: &[i64]) -> UpstreamPool {
    UpstreamPool {
        name: name.to_string(),
        strategy: UpstreamStrategy::Failover,
        servers: vec![upstream.url()],
        domains: domains.iter().map(|d| d.to_string()).collect(),
        groups: groups.to_vec(),
        internal: !domains.is_empty(),
        ..Default::default()
    }
}

struct Fixture {
    public: Upstream,
    office_a: Upstream,
    office_b: Upstream,
    pm: Arc<PoolManager>,
    cache: Arc<DnsCache>,
    stack: Arc<dyn DnsResolver>,
}

/// Each office's group sends `corp.example` to its own server; everyone else
/// resolves it publicly. `cache` is the stack's cache.
async fn fixture_with(cache: Arc<DnsCache>) -> Fixture {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let office_a = Upstream::spawn(Answer::Address(OFFICE_A_IP)).await;
    let office_b = Upstream::spawn(Answer::Address(OFFICE_B_IP)).await;
    let pm = Arc::new(
        PoolManager::new(
            vec![
                pool("public", &public, &[], &[]),
                pool("office-a", &office_a, &["corp.example"], &[GROUP_A]),
                pool("office-b", &office_b, &["corp.example"], &[GROUP_B]),
            ],
            None,
        )
        .await
        .unwrap(),
    );
    let stack = ResolverBuilder::new(Arc::clone(&pm), TIMEOUT_MS)
        .with_cache(Arc::clone(&cache), 7_200, 4)
        .build();
    Fixture {
        public,
        office_a,
        office_b,
        pm,
        cache,
        stack,
    }
}

async fn fixture() -> Fixture {
    fixture_with(refresh::refresh_cache(1_000, 0.75, 7_200)).await
}

fn query(domain: &str, group: Option<i64>) -> DnsQuery {
    DnsQuery::new(domain, RecordType::A).with_group(group)
}

/// Resolves as the use case does: the cache first, then the stack.
async fn resolve(stack: &Arc<dyn DnsResolver>, domain: &str, group: Option<i64>) -> Vec<IpAddr> {
    let query = query(domain, group);
    if let Some(hit) = stack.try_cache(&query) {
        return hit.addresses.as_ref().clone();
    }
    stack
        .resolve(&query)
        .await
        .unwrap_or_else(|e| panic!("{domain} for {group:?}: {e}"))
        .addresses
        .as_ref()
        .clone()
}

/// The fast-path probe the UDP handler makes.
fn probe(stack: &Arc<dyn DnsResolver>, domain: &str, group: Option<i64>) -> Option<Vec<IpAddr>> {
    stack
        .try_cache_str(domain, RecordType::A, group)
        .map(|hit| hit.addresses.as_ref().clone())
}

fn ips(ip: Ipv4Addr) -> Vec<IpAddr> {
    vec![IpAddr::V4(ip)]
}

#[tokio::test]
async fn test_each_group_gets_its_own_answer_and_hits_its_own_view() {
    let f = fixture().await;

    assert_eq!(
        resolve(&f.stack, NAME, Some(GROUP_A)).await,
        ips(OFFICE_A_IP)
    );
    assert_eq!(
        resolve(&f.stack, NAME, Some(GROUP_B)).await,
        ips(OFFICE_B_IP)
    );

    for (group, ip) in [(GROUP_A, OFFICE_A_IP), (GROUP_B, OFFICE_B_IP)] {
        let hit = f
            .stack
            .try_cache(&query(NAME, Some(group)))
            .unwrap_or_else(|| panic!("group {group} must hit its own view"));
        assert!(hit.cache_hit);
        assert_eq!(*hit.addresses, ips(ip));
    }
    assert_eq!(f.office_a.queries(), 1);
    assert_eq!(f.office_b.queries(), 1);
}

#[tokio::test]
async fn test_a_group_without_a_route_shares_the_default_entry() {
    let f = fixture().await;

    assert_eq!(
        resolve(&f.stack, NAME, Some(OTHER_GROUP)).await,
        ips(PUBLIC_IP)
    );
    // The shared entry must not answer a group that routes the name...
    assert_eq!(
        resolve(&f.stack, NAME, Some(GROUP_A)).await,
        ips(OFFICE_A_IP)
    );
    // ...and the group's answer must not leak into the shared entry.
    assert_eq!(probe(&f.stack, NAME, Some(100)), Some(ips(PUBLIC_IP)));
    assert_eq!(probe(&f.stack, NAME, None), Some(ips(PUBLIC_IP)));
    assert_eq!(f.public.queries(), 1);
}

#[tokio::test]
async fn test_fast_path_probe_returns_the_view_of_the_asking_group() {
    let f = fixture().await;
    resolve(&f.stack, NAME, Some(GROUP_A)).await;
    resolve(&f.stack, NAME, Some(GROUP_B)).await;

    assert_eq!(probe(&f.stack, NAME, Some(GROUP_A)), Some(ips(OFFICE_A_IP)));
    assert_eq!(probe(&f.stack, NAME, Some(GROUP_B)), Some(ips(OFFICE_B_IP)));
    assert_eq!(probe(&f.stack, NAME, Some(OTHER_GROUP)), None);
    assert_eq!(probe(&f.stack, NAME, None), None);
}

#[tokio::test]
async fn test_concurrent_queries_from_different_groups_never_coalesce() {
    let f = fixture().await;
    f.office_a.set_delay(Duration::from_millis(200));
    f.office_b.set_delay(Duration::from_millis(200));

    let qa = query(NAME, Some(GROUP_A));
    let qb = query(NAME, Some(GROUP_B));
    let (a, b) = tokio::join!(f.stack.resolve(&qa), f.stack.resolve(&qb));

    assert_eq!(*a.unwrap().addresses, ips(OFFICE_A_IP));
    assert_eq!(*b.unwrap().addresses, ips(OFFICE_B_IP));
    assert_eq!(f.office_a.queries(), 1);
    assert_eq!(f.office_b.queries(), 1);
}

#[tokio::test]
async fn test_concurrent_queries_from_the_same_group_coalesce() {
    let f = fixture().await;
    f.office_a.set_delay(Duration::from_millis(200));

    let q = query(NAME, Some(GROUP_A));
    let (first, second) = tokio::join!(f.stack.resolve(&q), f.stack.resolve(&q));

    assert_eq!(*first.unwrap().addresses, ips(OFFICE_A_IP));
    assert_eq!(*second.unwrap().addresses, ips(OFFICE_A_IP));
    assert_eq!(
        f.office_a.queries(),
        1,
        "same-group followers must join the leader"
    );
}

#[tokio::test]
async fn test_l1_never_serves_a_group_view_to_another_client() {
    // One thread: an L1 copy of the group's answer would be visible here.
    let f = fixture().await;
    resolve(&f.stack, NAME, Some(GROUP_A)).await;
    for _ in 0..3 {
        assert_eq!(probe(&f.stack, NAME, Some(GROUP_A)), Some(ips(OFFICE_A_IP)));
    }

    assert_eq!(probe(&f.stack, NAME, Some(OTHER_GROUP)), None);
    assert_eq!(probe(&f.stack, NAME, None), None);
}

#[tokio::test]
async fn test_a_negative_answer_stays_in_its_group_view() {
    let f = fixture().await;
    f.office_a.set(Answer::NxDomain);

    let negative = f
        .stack
        .resolve(&query(NAME, Some(GROUP_A)))
        .await
        .map(|r| r.addresses.is_empty());
    assert!(!matches!(negative, Ok(false)), "office A answered NXDOMAIN");

    assert_eq!(
        resolve(&f.stack, NAME, Some(GROUP_B)).await,
        ips(OFFICE_B_IP)
    );
    assert_eq!(f.office_b.queries(), 1);
}

#[tokio::test]
async fn test_refresh_renews_a_group_entry_through_the_group_pool() {
    // Due a second after it is stored, and never cold.
    let f = fixture_with(refresh::refresh_cache(100, 0.0, u64::MAX)).await;
    let maintenance = ResolverBuilder::new(Arc::clone(&f.pm), TIMEOUT_MS).build();
    let _worker = refresh::start_worker(&f.cache, maintenance, refresh::no_ranking(), true);

    assert_eq!(
        resolve(&f.stack, NAME, Some(GROUP_A)).await,
        ips(OFFICE_A_IP)
    );

    let renewed = refresh::wait_until(Duration::from_secs(5), || f.office_a.queries() >= 2).await;
    assert!(
        renewed,
        "the group entry was not renewed through the group's pool"
    );
    assert_eq!(
        f.public.queries(),
        0,
        "the renewal leaked to the default pool"
    );
    assert_eq!(f.office_b.queries(), 0);
    assert_eq!(probe(&f.stack, NAME, Some(GROUP_A)), Some(ips(OFFICE_A_IP)));
    assert_eq!(probe(&f.stack, NAME, None), None);
}

#[tokio::test]
async fn test_cname_target_of_a_group_routed_answer_is_not_cached() {
    let f = fixture().await;
    f.office_a
        .set(Answer::Cname("lb.cdn.example.", OFFICE_A_IP));

    assert_eq!(
        resolve(&f.stack, "app.corp.example", Some(GROUP_A)).await,
        ips(OFFICE_A_IP)
    );

    for target in TARGET_FORMS {
        assert_eq!(probe(&f.stack, target, None), None, "{target}");
        assert_eq!(probe(&f.stack, target, Some(OTHER_GROUP)), None, "{target}");
    }
}

#[tokio::test]
async fn test_cname_target_of_an_every_client_routed_answer_is_not_cached() {
    let public = Upstream::spawn(Answer::Address(PUBLIC_IP)).await;
    let office = Upstream::spawn(Answer::Cname("lb.cdn.example.", OFFICE_A_IP)).await;
    let pm = Arc::new(
        PoolManager::new(
            vec![
                pool("public", &public, &[], &[]),
                pool("office", &office, &["corp.example"], &[]),
            ],
            None,
        )
        .await
        .unwrap(),
    );
    let stack = ResolverBuilder::new(pm, TIMEOUT_MS)
        .with_cache(refresh::refresh_cache(1_000, 0.75, 7_200), 7_200, 4)
        .build();

    assert_eq!(
        resolve(&stack, "app.corp.example", None).await,
        ips(OFFICE_A_IP)
    );
    assert_eq!(
        probe(&stack, "app.corp.example", None),
        Some(ips(OFFICE_A_IP))
    );
    for target in TARGET_FORMS {
        assert_eq!(probe(&stack, target, None), None, "{target}");
    }
}

#[tokio::test]
async fn test_a_local_record_wins_over_a_group_route() {
    let f = fixture().await;
    f.cache.insert_permanent(
        "nas.corp.example",
        RecordType::A,
        refresh::address(LOCAL_IP),
        300,
    );
    let local = vec![LOCAL_IP.parse::<IpAddr>().unwrap()];

    assert_eq!(
        probe(&f.stack, "nas.corp.example", Some(GROUP_A)),
        Some(local.clone())
    );
    assert_eq!(
        resolve(&f.stack, "nas.corp.example", Some(GROUP_B)).await,
        local
    );
    assert_eq!(f.office_a.queries() + f.office_b.queries(), 0);
}

#[tokio::test]
async fn test_group_view_entries_are_evicted_like_any_other() {
    let f = fixture_with(refresh::refresh_cache(16, 0.75, 7_200)).await;
    for i in 0..24 {
        resolve(&f.stack, &format!("h{i}.corp.example"), Some(GROUP_A)).await;
    }
    let before = f.cache.len();
    assert!(before > 16);

    f.cache.evict_entries();

    assert!(
        f.cache.len() < before,
        "group view entries must be evictable"
    );
}
