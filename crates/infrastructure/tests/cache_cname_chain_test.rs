//! A cached answer keeps the CNAME chain it came through, so a hit can be
//! checked against the block filter the way a fresh answer is (CNAME
//! cloaking). The chain has to survive every way a cached answer reaches a
//! client: an L1 hit, an L2 hit, a wire answer, and a renewal.

#[path = "support/refresh.rs"]
mod refresh;

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{CNAME, MX};
use hickory_proto::rr::{Name, RData, Record, RecordType as WireType};
use hickory_proto::serialize::binary::BinEncodable;
use refresh::{no_ranking, refresh_cache, start_worker, wait_until};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ALIAS: &str = "metrics.site.example";
const TRACKER: &str = "x.tracker.example";

/// Answers every query with `chain`: addresses for A, an upstream MX
/// message through the chain for MX. `set_chain` changes it for renewals.
struct ChainResolver {
    chain: Mutex<Vec<Arc<str>>>,
}

impl ChainResolver {
    fn new(chain: &[&str]) -> Arc<Self> {
        let resolver = Arc::new(Self {
            chain: Mutex::new(Vec::new()),
        });
        resolver.set_chain(chain);
        resolver
    }

    fn set_chain(&self, chain: &[&str]) {
        *self.chain.lock().unwrap() = chain.iter().map(|name| Arc::from(*name)).collect();
    }
}

/// An upstream MX answer for `owner` that goes through `chain`.
fn mx_through(owner: &str, chain: &[Arc<str>]) -> Bytes {
    let owner = Name::from_str(&format!("{owner}.")).unwrap();
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(owner.clone(), WireType::MX));
    let mut name = owner;
    for hop in chain {
        let target = Name::from_str(&format!("{hop}.")).unwrap();
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        name = target;
    }
    let exchange = Name::from_str("mx1.site.example.").unwrap();
    msg.add_answer(Record::from_rdata(
        name,
        300,
        RData::MX(MX::new(10, exchange)),
    ));
    Bytes::from(msg.to_bytes().unwrap())
}

#[async_trait]
impl DnsResolver for ChainResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let chain = self.chain.lock().unwrap().clone();
        let mut resolution = DnsResolution::new(vec![], false);
        if query.record_type == RecordType::MX {
            resolution.upstream_wire_data = Some(mx_through(&query.domain, &chain));
        } else {
            resolution.addresses = Arc::new(vec!["203.0.113.9".parse::<IpAddr>().unwrap()]);
        }
        resolution.cname_chain = chain.into();
        resolution.min_ttl = Some(300);
        Ok(resolution)
    }
}

fn query(domain: &str, record_type: RecordType) -> DnsQuery {
    DnsQuery::new(Arc::from(domain), record_type)
}

/// The chain a cache probe for `domain` reports.
fn cached_chain(
    resolver: &CachedResolver,
    domain: &str,
    record_type: RecordType,
) -> Option<Vec<String>> {
    resolver.try_cache(&query(domain, record_type)).map(|hit| {
        hit.cname_chain
            .iter()
            .map(|name| name.to_string())
            .collect()
    })
}

/// The same probe on a fresh thread, whose empty L1 sends it to L2.
fn cached_chain_from_l2(
    resolver: &Arc<CachedResolver>,
    domain: &'static str,
    record_type: RecordType,
) -> Option<Vec<String>> {
    let resolver = Arc::clone(resolver);
    std::thread::spawn(move || cached_chain(&resolver, domain, record_type))
        .join()
        .unwrap()
}

fn cached_resolver(upstream: Arc<ChainResolver>) -> Arc<CachedResolver> {
    Arc::new(CachedResolver::new(
        upstream,
        refresh_cache(1_000, 0.75, 7_200),
        300,
        4,
    ))
}

#[tokio::test]
async fn test_an_l1_hit_keeps_the_cname_chain() {
    let resolver = cached_resolver(ChainResolver::new(&[TRACKER]));

    resolver
        .resolve(&query(ALIAS, RecordType::A))
        .await
        .unwrap();

    // The insert left a copy in this thread's L1, which answers this probe.
    assert_eq!(
        cached_chain(&resolver, ALIAS, RecordType::A),
        Some(vec![TRACKER.to_string()])
    );
}

#[tokio::test]
async fn test_an_l2_hit_keeps_the_cname_chain() {
    let resolver = cached_resolver(ChainResolver::new(&[TRACKER]));

    resolver
        .resolve(&query(ALIAS, RecordType::A))
        .await
        .unwrap();

    assert_eq!(
        cached_chain_from_l2(&resolver, ALIAS, RecordType::A),
        Some(vec![TRACKER.to_string()])
    );
}

#[tokio::test]
async fn test_a_wire_hit_keeps_the_cname_chain() {
    let resolver = cached_resolver(ChainResolver::new(&[TRACKER]));

    resolver
        .resolve(&query(ALIAS, RecordType::MX))
        .await
        .unwrap();

    assert_eq!(
        cached_chain(&resolver, ALIAS, RecordType::MX),
        Some(vec![TRACKER.to_string()])
    );
}

#[tokio::test]
async fn test_a_renewal_replaces_the_cname_chain() {
    let upstream = ChainResolver::new(&["old.cdn.example"]);
    let cache = refresh_cache(1_000, 0.75, 7_200);
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&upstream) as Arc<dyn DnsResolver>,
        cache.clone(),
        300,
        4,
    ));
    resolver
        .resolve(&query(ALIAS, RecordType::A))
        .await
        .unwrap();
    let worker = start_worker(
        &cache,
        Arc::clone(&upstream) as Arc<dyn DnsResolver>,
        no_ranking(),
    );

    upstream.set_chain(&[TRACKER]);
    worker
        .stale
        .send((Arc::from(ALIAS), RecordType::A, 0))
        .await
        .unwrap();

    let renewed = wait_until(Duration::from_secs(5), || {
        cached_chain_from_l2(&resolver, ALIAS, RecordType::A) == Some(vec![TRACKER.to_string()])
    })
    .await;
    assert!(
        renewed,
        "the renewed entry reports {:?}",
        cached_chain_from_l2(&resolver, ALIAS, RecordType::A)
    );
}

#[tokio::test]
async fn test_an_answer_without_a_chain_reports_none() {
    let resolver = cached_resolver(ChainResolver::new(&[]));

    resolver
        .resolve(&query(ALIAS, RecordType::A))
        .await
        .unwrap();

    assert_eq!(
        cached_chain_from_l2(&resolver, ALIAS, RecordType::A),
        Some(vec![])
    );
}
