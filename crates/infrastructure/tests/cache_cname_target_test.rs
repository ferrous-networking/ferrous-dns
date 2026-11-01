//! A CNAME chain's target is not cached under its own name: only the queried
//! name's answer is. The target may belong to something else, such as a
//! conditional pool, a wildcard local record, a name under `local_domain` or a
//! local record, and an upstream's answer for another name must not speak for
//! it (#325).

#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{
    DnsQuery, DomainError, LocalDnsRecord, RecordType, UpstreamPool, UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::resolver::{
    CachedResolver, LocalWildcardResolver, ResolverBuilder,
};
use ferrous_dns_infrastructure::dns::{CachedAddresses, CachedData, PoolManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const TIMEOUT_MS: u64 = 2_000;

/// Answers every query with one address through `chain`.
struct CnameChainResolver {
    cname_chain: Arc<[Arc<str>]>,
}

#[async_trait]
impl DnsResolver for CnameChainResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Ok(DnsResolution {
            cname_chain: Arc::clone(&self.cname_chain),
            min_ttl: Some(300),
            ..DnsResolution::new(vec![IpAddr::V4(PUBLIC_IP)], false)
        })
    }
}

fn make_query(domain: &str) -> DnsQuery {
    DnsQuery::new(Arc::from(domain), RecordType::A)
}

fn ips(ip: Ipv4Addr) -> Vec<IpAddr> {
    vec![IpAddr::V4(ip)]
}

fn pool(name: &str, upstream: &Upstream, domains: &[&str]) -> UpstreamPool {
    UpstreamPool {
        name: name.to_string(),
        strategy: UpstreamStrategy::Failover,
        servers: vec![upstream.url()],
        domains: domains.iter().map(|domain| domain.to_string()).collect(),
        internal: !domains.is_empty(),
        ..Default::default()
    }
}

/// The server's resolver stack over `pools`; `extra` adds the local layers a
/// test needs.
async fn stack(
    pools: Vec<UpstreamPool>,
    extra: impl FnOnce(ResolverBuilder) -> ResolverBuilder,
) -> Arc<dyn DnsResolver> {
    let pm = Arc::new(PoolManager::new(pools, None).await.unwrap());
    extra(ResolverBuilder::new(pm, TIMEOUT_MS).with_cache(
        refresh::refresh_cache(1_000, 0.75, 7_200),
        7_200,
        4,
    ))
    .build()
}

/// As the use case resolves: the cache first, then the stack.
async fn resolve(stack: &Arc<dyn DnsResolver>, domain: &str) -> Vec<IpAddr> {
    let query = make_query(domain);
    if let Some(hit) = stack.try_cache(&query) {
        if hit.has_response_data() {
            return hit.addresses.as_ref().clone();
        }
    }
    stack
        .resolve(&query)
        .await
        .unwrap()
        .addresses
        .as_ref()
        .clone()
}

#[tokio::test]
async fn should_not_cache_the_target_of_a_cname_chain() {
    let cache = refresh::refresh_cache(1_000, 0.75, 7_200);
    let resolver = CachedResolver::new(
        Arc::new(CnameChainResolver {
            cname_chain: Arc::from([Arc::from("cdn.foo.com")]),
        }),
        cache.clone(),
        300,
        4,
    );

    resolver.resolve(&make_query("www.foo.com")).await.unwrap();

    assert!(cache.get("www.foo.com", &RecordType::A).is_some());
    assert!(
        cache.get("cdn.foo.com", &RecordType::A).is_none(),
        "the chain target was cached under its own name"
    );
}

#[tokio::test]
async fn should_not_cache_the_target_of_a_wire_cname_chain() {
    let public = Upstream::spawn(Answer::Cname("lb.cdn.example.", PUBLIC_IP)).await;
    let stack = stack(vec![pool("public", &public, &[])], |builder| builder).await;

    resolve(&stack, "www.site.example").await;

    assert!(stack.try_cache(&make_query("lb.cdn.example")).is_none());
}

/// Split horizon: a public name that CNAMEs into a routed zone must not repoint
/// the routed name for every client.
#[tokio::test]
async fn should_not_repoint_a_name_a_conditional_pool_answers() {
    let public = Upstream::spawn(Answer::Cname("app.corp.example.", PUBLIC_IP)).await;
    let office = Upstream::spawn(Answer::Address(Ipv4Addr::new(10, 1, 1, 1))).await;
    let stack = stack(
        vec![
            pool("public", &public, &[]),
            pool("office", &office, &["corp.example"]),
        ],
        |builder| builder,
    )
    .await;
    assert_eq!(
        resolve(&stack, "app.corp.example").await,
        ips(Ipv4Addr::new(10, 1, 1, 1))
    );

    resolve(&stack, "portal.saas.example").await;

    assert_eq!(
        resolve(&stack, "app.corp.example").await,
        ips(Ipv4Addr::new(10, 1, 1, 1)),
        "the routed name answers with the public upstream's address"
    );
}

#[tokio::test]
async fn should_not_override_a_wildcard_local_record() {
    let public = Upstream::spawn(Answer::Cname("nas.home.lan.", PUBLIC_IP)).await;
    let wildcard = LocalDnsRecord {
        hostname: "*".into(),
        domain: Some("home.lan".into()),
        ip: IpAddr::V4(LOCAL_IP),
        record_type: "A".parse().unwrap(),
        ttl: Some(120),
    };
    let map = LocalWildcardResolver::map_from_local_records(&[wildcard], None);
    let stack = stack(vec![pool("public", &public, &[])], |builder| {
        builder.with_local_wildcards(map)
    })
    .await;
    assert_eq!(resolve(&stack, "nas.home.lan").await, ips(LOCAL_IP));

    resolve(&stack, "evil.example.com").await;

    assert_eq!(
        resolve(&stack, "nas.home.lan").await,
        ips(LOCAL_IP),
        "the wildcard local record lost to an upstream chain target"
    );
}

#[tokio::test]
async fn should_not_answer_a_local_domain_name_from_a_public_chain() {
    let public = Upstream::spawn(Answer::Cname("nas.lan.", PUBLIC_IP)).await;
    let router = Upstream::spawn(Answer::Address(LOCAL_IP)).await;
    let router_addr: SocketAddr = router.url().trim_start_matches("udp://").parse().unwrap();
    let stack = stack(vec![pool("public", &public, &[])], |builder| {
        builder
            .with_local_domain(Some("lan".into()))
            .with_local_dns_server(Some(router_addr))
    })
    .await;

    resolve(&stack, "evil.example.com").await;

    assert_eq!(
        resolve(&stack, "nas.lan").await,
        ips(LOCAL_IP),
        "a local-domain name was answered from a public chain"
    );
    assert_eq!(router.queries(), 1, "the local DNS server was never asked");
}

/// A chain ending in a local name must not overwrite that name's configured
/// record, or any upstream domain could repoint a local host.
#[tokio::test]
async fn should_not_overwrite_a_local_record_with_a_cname_target() {
    let local = IpAddr::V4(LOCAL_IP);
    let public = Upstream::spawn(Answer::Cname("nas.home.lan.", PUBLIC_IP)).await;
    let cache = refresh::refresh_cache(1_000, 0.75, 7_200);
    cache.insert_permanent(
        "nas.home.lan",
        RecordType::A,
        CachedData::IpAddresses(CachedAddresses::new(Arc::new(vec![local]))),
        300,
    );
    let pm = Arc::new(
        PoolManager::new(vec![pool("public", &public, &[])], None)
            .await
            .unwrap(),
    );
    let stack = ResolverBuilder::new(pm, TIMEOUT_MS)
        .with_cache(cache, 300, 4)
        .build();

    resolve(&stack, "evil.example.com").await;

    assert_eq!(resolve(&stack, "nas.home.lan").await, vec![local]);
}
