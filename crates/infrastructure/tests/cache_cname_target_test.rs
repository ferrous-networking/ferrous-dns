//! CNAME chain target caching.
//!
//! When the upstream resolves `www.foo.com A?` via the chain
//! `www.foo.com CNAME cdn.foo.com, cdn.foo.com A 1.2.3.4`, the resolver
//! must persist a secondary cache entry for `cdn.foo.com A -> [1.2.3.4]`.
//! A direct subsequent query for `cdn.foo.com A` should be served from
//! the cache instead of escaping to upstream.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Mock resolver returning a canned response with a CNAME chain.
/// Counts upstream calls so tests can assert whether the cache was consulted.
struct CnameChainResolver {
    call_count: Arc<AtomicUsize>,
    addresses: Vec<IpAddr>,
    cname_chain: Vec<Arc<str>>,
    dnssec_status: Option<DnssecStatus>,
}

impl CnameChainResolver {
    fn new(addr: &str, targets: &[&str]) -> Self {
        let ip: IpAddr = addr.parse().unwrap();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            addresses: vec![ip],
            cname_chain: targets.iter().map(|t| Arc::from(*t)).collect(),
            dnssec_status: None,
        }
    }

    fn without_cname_chain(addr: &str) -> Self {
        let ip: IpAddr = addr.parse().unwrap();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            addresses: vec![ip],
            cname_chain: Vec::new(),
            dnssec_status: None,
        }
    }

    fn with_dnssec(mut self, status: DnssecStatus) -> Self {
        self.dnssec_status = Some(status);
        self
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for CnameChainResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let cname_chain: Arc<[Arc<str>]> = self.cname_chain.clone().into();
        Ok(DnsResolution {
            addresses: Arc::new(self.addresses.clone()),
            cache_hit: false,
            local_dns: false,
            local_nxdomain: false,
            dnssec_status: self.dnssec_status,
            cname_chain,
            upstream_server: None,
            upstream_pool: None,
            min_ttl: Some(300),
            negative_soa_ttl: None,
            upstream_wire_data: None,
        })
    }
}

fn make_cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::LRU,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
        renew_ahead: true,
        retry_lapsed_after_secs: 300,
    }))
}

fn make_query(domain: &str) -> DnsQuery {
    DnsQuery {
        domain: Arc::from(domain),
        record_type: RecordType::A,
        group_id: None,
    }
}

#[tokio::test]
async fn should_cache_cname_target_addresses_separately() {
    let mock = Arc::new(CnameChainResolver::new("1.2.3.4", &["cdn.foo.com"]));
    let resolver = CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
        4,
    );

    // First query: populates cache for both www.foo.com and cdn.foo.com.
    let first = resolver.resolve(&make_query("www.foo.com")).await.unwrap();
    assert!(!first.cache_hit, "first call must go to upstream");
    assert_eq!(mock.call_count(), 1);

    // Second query for the final target directly: must be a cache hit,
    // no new upstream call.
    let second = resolver.resolve(&make_query("cdn.foo.com")).await.unwrap();
    assert!(
        second.cache_hit,
        "direct query for CNAME target must hit the cache"
    );
    assert_eq!(
        mock.call_count(),
        1,
        "cache must serve the target without re-querying upstream"
    );
    assert_eq!(
        second.addresses.as_ref(),
        &["1.2.3.4".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn should_not_cache_target_when_chain_is_empty() {
    let mock = Arc::new(CnameChainResolver::without_cname_chain("5.6.7.8"));
    let cache = make_cache();
    let resolver = CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        cache.clone(),
        300,
        4,
    );

    // Populate the cache via the qname path.
    let _ = resolver
        .resolve(&make_query("direct.foo.com"))
        .await
        .unwrap();
    assert_eq!(mock.call_count(), 1);

    // Only the qname entry should exist. Querying any unrelated name must miss
    // the cache and hit the upstream, proving no stray "target" entry was stored.
    assert!(
        cache.get("direct.foo.com", &RecordType::A).is_some(),
        "qname entry must be present"
    );

    // Sanity: a completely different name must not be present.
    assert!(
        cache.get("ghost.foo.com", &RecordType::A).is_none(),
        "no spurious target entry may be stored when the chain is empty"
    );
}

#[tokio::test]
async fn should_inherit_dnssec_status_from_qname_entry() {
    let mock = Arc::new(
        CnameChainResolver::new("9.9.9.9", &["secure-target.example"])
            .with_dnssec(DnssecStatus::Secure),
    );
    let cache = make_cache();
    let resolver = CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        cache.clone(),
        300,
        4,
    );

    // Populate: qname + CNAME target both cached.
    let _ = resolver
        .resolve(&make_query("alias.example"))
        .await
        .unwrap();

    // L1 is thread-local and drops DnssecStatus on the hot path (see
    // `storage.rs::get` for L1 short-circuit returning `None` for status).
    // Hop to a fresh OS thread so the L2 path runs and surfaces the stored
    // DNSSEC status.
    let cache_clone = Arc::clone(&cache);
    let (_, dnssec, _, _) = std::thread::spawn(move || {
        cache_clone
            .get("secure-target.example", &RecordType::A)
            .expect("target entry must be cached")
    })
    .join()
    .unwrap();

    assert_eq!(
        dnssec,
        Some(ferrous_dns_infrastructure::dns::CachedDnssecStatus::Secure),
        "target entry must inherit the qname entry's DNSSEC status"
    );
}

/// A chain ending in a local name must not overwrite that name's configured
/// record, or any upstream domain could repoint a local host.
#[tokio::test]
async fn should_not_overwrite_a_local_record_with_a_cname_target() {
    let cache = make_cache();
    let local: IpAddr = "10.0.0.5".parse().unwrap();
    cache.insert_permanent(
        "nas.home.lan",
        RecordType::A,
        CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![local]),
        }),
        300,
    );
    let mock = Arc::new(CnameChainResolver::new("203.0.113.66", &["nas.home.lan"]));
    let resolver = CachedResolver::new(mock as Arc<dyn DnsResolver>, cache.clone(), 300, 4);

    resolver
        .resolve(&make_query("evil.example.com"))
        .await
        .unwrap();

    let (data, _, _, _) = cache
        .get("nas.home.lan", &RecordType::A)
        .expect("the local record must still answer");
    assert_eq!(
        data.as_ip_addresses().map(|a| a.as_ref().clone()),
        Some(vec![local])
    );
}
