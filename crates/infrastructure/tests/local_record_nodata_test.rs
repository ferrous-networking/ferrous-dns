use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::RecordType::{A, AAAA, CNAME, TXT};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, LocalRecordType, RecordType};
use ferrous_dns_infrastructure::dns::resolver::{CachedResolver, LocalWildcardResolver};
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
}

impl Upstream {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl DnsResolver for Upstream {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let address = match query.record_type {
            RecordType::A => ip("203.0.113.7"),
            RecordType::AAAA => ip("2001:db8::7"),
            _ => return Err(DomainError::NxDomain),
        };
        Ok(DnsResolution::new(vec![address], false))
    }
}

fn setup() -> (Arc<DnsCache>, Arc<CachedResolver>, Arc<Upstream>) {
    let cache = Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.0,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }));
    let upstream = Arc::new(Upstream::default());
    let resolver = Arc::new(CachedResolver::new(upstream.clone(), cache.clone(), 300, 4));
    (cache, resolver, upstream)
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn insert_local(cache: &DnsCache, name: &str, record_type: RecordType, address: &str) {
    cache.insert_permanent(
        name,
        record_type,
        CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![ip(address)]),
        }),
        300,
    );
}

async fn answer(resolver: &dyn DnsResolver, query: &DnsQuery) -> DnsResolution {
    resolver.resolve(query).await.unwrap()
}

fn assert_address(resolution: &DnsResolution, address: &str) {
    assert_eq!(resolution.addresses.as_ref(), &[ip(address)]);
}

fn assert_local_nodata(resolution: &DnsResolution) {
    assert!(resolution.local_dns);
    assert!(resolution.addresses.is_empty());
    assert!(resolution.cname_chain.is_empty());
    assert!(resolution.upstream_wire_data.is_none());
}

#[tokio::test]
async fn test_local_nodata_tracks_live_record_families() {
    let (cache, resolver, upstream) = setup();
    let name = "families.local.test";
    let a = DnsQuery::new(name, A);
    let aaaa = DnsQuery::new(name, AAAA);
    let txt = DnsQuery::new(name, TXT);
    insert_local(&cache, name, A, "192.0.2.10");
    // Replacement must not leave duplicate ownership after removal.
    insert_local(&cache, name, A, "192.0.2.11");

    assert_local_nodata(&answer(&*resolver, &aaaa).await);
    assert_local_nodata(
        &resolver
            .try_cache_str("FAMILIES.LOCAL.TEST", AAAA, None)
            .unwrap(),
    );
    assert_address(&answer(&*resolver, &a).await, "192.0.2.11");
    assert_local_nodata(&answer(&*resolver, &txt).await);

    insert_local(&cache, name, AAAA, "2001:db8::10");
    assert_address(&answer(&*resolver, &aaaa).await, "2001:db8::10");
    assert!(cache.remove(name, &A));
    assert_local_nodata(&answer(&*resolver, &a).await);
    assert_local_nodata(&answer(&*resolver, &txt).await);
    assert_address(&answer(&*resolver, &aaaa).await, "2001:db8::10");
    assert_eq!(upstream.calls(), 0);

    assert!(cache.remove(name, &AAAA));
    for (query, address) in [(&a, "203.0.113.7"), (&aaaa, "2001:db8::7")] {
        let result = answer(&*resolver, query).await;
        assert_address(&result, address);
        assert!(!result.local_dns);
    }
    assert!(matches!(
        resolver.resolve(&txt).await,
        Err(DomainError::NxDomain)
    ));
    assert_eq!(upstream.calls(), 3);
}

#[tokio::test]
async fn test_new_local_ownership_overrides_positive_and_negative_cache_entries() {
    let (cache, resolver, upstream) = setup();
    let name = "precedence.local.test";
    let a = DnsQuery::new(name, A);
    let aaaa = DnsQuery::new(name, AAAA);
    let txt = DnsQuery::new(name, TXT);

    assert_address(&answer(&*resolver, &a).await, "203.0.113.7");
    assert_address(&answer(&*resolver, &aaaa).await, "2001:db8::7");
    assert!(matches!(
        resolver.resolve(&txt).await,
        Err(DomainError::NxDomain)
    ));
    assert_eq!(upstream.calls(), 3);

    insert_local(&cache, name, A, "192.0.2.20");
    assert_address(&answer(&*resolver, &a).await, "192.0.2.20");
    assert_local_nodata(&answer(&*resolver, &aaaa).await);
    assert_local_nodata(&answer(&*resolver, &txt).await);
    assert_eq!(upstream.calls(), 3);

    // Local NODATA must shadow, not overwrite, the upstream cache entries.
    assert!(cache.remove(name, &A));
    let result = answer(&*resolver, &aaaa).await;
    assert_address(&result, "2001:db8::7");
    assert!(!result.local_dns);
    assert!(matches!(
        resolver.resolve(&txt).await,
        Err(DomainError::NxDomain)
    ));
    assert_eq!(upstream.calls(), 3);
}

#[tokio::test]
async fn test_cache_clear_preserves_local_nodata() {
    let (cache, resolver, upstream) = setup();
    let name = "clear.local.test";
    let a = DnsQuery::new(name, A);
    let aaaa = DnsQuery::new(name, AAAA);
    let txt = DnsQuery::new(name, TXT);
    insert_local(&cache, name, A, "192.0.2.30");
    assert_local_nodata(&answer(&*resolver, &aaaa).await);

    cache.clear();

    assert_address(&answer(&*resolver, &a).await, "192.0.2.30");
    assert_local_nodata(&answer(&*resolver, &aaaa).await);
    assert_local_nodata(&answer(&*resolver, &txt).await);
    assert_eq!(upstream.calls(), 0);
}

#[tokio::test]
async fn test_exact_local_nodata_beats_covering_wildcard_until_last_record_removed() {
    let (cache, cached_resolver, upstream) = setup();
    let name = "exact.wildcard.test";
    insert_local(&cache, name, A, "192.0.2.40");
    let map = LocalWildcardResolver::map_from_local_records(
        &[LocalDnsRecord {
            hostname: "*".to_string(),
            domain: Some("wildcard.test".to_string()),
            ip: "2001:db8::99".parse().unwrap(),
            record_type: LocalRecordType::AAAA,
            ttl: Some(120),
        }],
        None,
    );
    let resolver = LocalWildcardResolver::new(cached_resolver, map);
    let a = DnsQuery::new(name, A);
    let aaaa = DnsQuery::new(name, AAAA);
    let other = DnsQuery::new("other.wildcard.test", AAAA);

    assert_local_nodata(&answer(&resolver, &aaaa).await);
    assert_address(&answer(&resolver, &a).await, "192.0.2.40");
    assert_address(&answer(&resolver, &other).await, "2001:db8::99");

    assert!(cache.remove(name, &A));
    assert_address(&answer(&resolver, &aaaa).await, "2001:db8::99");
    assert_eq!(upstream.calls(), 0);
}

#[tokio::test]
async fn test_non_address_permanent_entry_survives_clear_without_owning_missing_types() {
    let (cache, resolver, upstream) = setup();
    let name = "non-address.permanent.local.test";
    let a = DnsQuery::new(name, A);
    let aaaa = DnsQuery::new(name, AAAA);
    let cname = DnsQuery::new(name, CNAME);
    let txt = DnsQuery::new(name, TXT);
    cache.insert_permanent(
        name,
        CNAME,
        CachedData::CanonicalName(Arc::from("target.local.test")),
        300,
    );
    insert_local(&cache, name, A, "192.0.2.50");
    insert_local(&cache, name, AAAA, "2001:db8::50");
    cache.clear();

    assert_address(&answer(&*resolver, &a).await, "192.0.2.50");
    assert_address(&answer(&*resolver, &aaaa).await, "2001:db8::50");
    assert!(cache.remove(name, &A));
    assert!(cache.remove(name, &AAAA));
    cache.rotate_bloom();
    cache.rotate_bloom();
    let canonical = answer(&*resolver, &cname).await;
    assert!(canonical.local_dns);
    assert_eq!(
        canonical.cname_chain.as_ref(),
        &[Arc::<str>::from("target.local.test")]
    );
    assert_eq!(upstream.calls(), 0);

    let result = answer(&*resolver, &a).await;
    assert_address(&result, "203.0.113.7");
    assert!(!result.local_dns);
    assert!(matches!(
        resolver.resolve(&txt).await,
        Err(DomainError::NxDomain)
    ));
    assert_eq!(upstream.calls(), 2);

    assert!(cache.remove(name, &CNAME));
    assert!(matches!(
        resolver.resolve(&cname).await,
        Err(DomainError::NxDomain)
    ));
    assert_eq!(upstream.calls(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_coalesced_followers_keep_local_nodata() {
    use ferrous_dns_infrastructure::dns::{CachedDnssecStatus, DnsCacheAccess, LocalRecordStatus};
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;
    use tokio::sync::Notify;

    struct DeferredOwnership {
        cache: Arc<DnsCache>,
        checks: AtomicUsize,
        checkpoint: Arc<Notify>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl DnsCacheAccess for DeferredOwnership {
        fn get(
            &self,
            domain: &str,
            kind: &RecordType,
        ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)> {
            self.cache.get(domain, kind)
        }

        fn local_record_status(&self, domain: &str, kind: &RecordType) -> LocalRecordStatus {
            match self.checks.fetch_add(1, Ordering::SeqCst) {
                // The leader's in-flight check: pause it until the follower
                // has subscribed.
                0 => {
                    self.checkpoint.notify_one();
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    self.cache.local_record_status(domain, kind)
                }
                _ => self.cache.local_record_status(domain, kind),
            }
        }

        fn insert(
            &self,
            domain: &str,
            kind: RecordType,
            data: CachedData,
            ttl: u32,
            status: Option<CachedDnssecStatus>,
            local_dns: bool,
        ) {
            DnsCacheAccess::insert(&*self.cache, domain, kind, data, ttl, status, local_dns);
        }
    }

    let (cache, _, upstream) = setup();
    let name = "coalesced.local.test";
    insert_local(&cache, name, A, "192.0.2.70");
    let checkpoint = Arc::new(Notify::new());
    let (release_tx, release_rx) = mpsc::channel();
    let resolver = Arc::new(CachedResolver::new(
        upstream.clone(),
        Arc::new(DeferredOwnership {
            cache,
            checks: AtomicUsize::new(0),
            checkpoint: checkpoint.clone(),
            release: Mutex::new(release_rx),
        }),
        300,
        4,
    ));
    let leader_resolver = resolver.clone();
    let leader =
        tokio::spawn(async move { leader_resolver.resolve(&DnsQuery::new(name, AAAA)).await });
    tokio::time::timeout(Duration::from_secs(5), checkpoint.notified())
        .await
        .unwrap();

    let query = DnsQuery::new(name, AAAA);
    let mut follower = Box::pin(resolver.resolve(&query));
    // Pending proves the follower subscribed before the leader resumes.
    assert!(futures::poll!(&mut follower).is_pending());
    release_tx.send(()).unwrap();
    let (leader, follower) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(leader, follower)
    })
    .await
    .unwrap();
    assert_local_nodata(&leader.unwrap().unwrap());
    assert_local_nodata(&follower.unwrap());
    assert_eq!(upstream.calls(), 0);
}
