use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{DnsCache, DnsCacheConfig, EvictionStrategy};
use futures::future::join_all;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct DelayedMockResolver {
    call_count: Arc<AtomicUsize>,
    delay_ms: u64,
    response: Option<DnsResolution>,
}

impl DelayedMockResolver {
    fn new(delay_ms: u64, addr: &str) -> Self {
        let ip: IpAddr = addr.parse().unwrap();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            delay_ms,
            response: Some(DnsResolution::new(vec![ip], false)),
        }
    }

    fn new_failing(delay_ms: u64) -> Self {
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            delay_ms,
            response: None,
        }
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for DelayedMockResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        match &self.response {
            Some(r) => Ok(r.clone()),
            None => Err(DomainError::NxDomain),
        }
    }
}

fn make_cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 2.0,
        refresh_threshold: 0.75,

        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
    }))
}

fn make_query(domain: &str, record_type: RecordType) -> DnsQuery {
    DnsQuery {
        domain: Arc::from(domain),
        record_type,
    }
}

#[tokio::test]
async fn test_coalescing_deduplicates_concurrent_queries() {
    let mock = Arc::new(DelayedMockResolver::new(50, "1.2.3.4"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve(&make_query("example.com", RecordType::A)).await })
        })
        .collect();

    let results: Vec<_> = join_all(tasks).await;

    assert_eq!(mock.call_count(), 1, "expected exactly 1 upstream call");

    for result in &results {
        let res = result.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(
            res.addresses.as_ref(),
            &["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }
}

#[tokio::test]
async fn test_coalescing_cache_hit_flag_for_waiters() {
    let mock = Arc::new(DelayedMockResolver::new(50, "1.2.3.4"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve(&make_query("example.com", RecordType::A)).await })
        })
        .collect();

    let results: Vec<_> = join_all(tasks).await;

    assert_eq!(mock.call_count(), 1);

    let cache_hits = results
        .iter()
        .filter(|r| r.as_ref().unwrap().as_ref().unwrap().cache_hit)
        .count();
    let upstream_hits = results
        .iter()
        .filter(|r| !r.as_ref().unwrap().as_ref().unwrap().cache_hit)
        .count();

    assert_eq!(upstream_hits, 1, "exactly 1 result should be from upstream");
    assert_eq!(
        cache_hits, 5,
        "exactly 5 results should be marked as cache hits"
    );
}

#[tokio::test]
async fn test_coalescing_error_propagation_to_waiters() {
    let mock = Arc::new(DelayedMockResolver::new_failing(50));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move {
                r.resolve(&make_query("nxdomain.example", RecordType::A))
                    .await
            })
        })
        .collect();

    let results: Vec<_> = join_all(tasks).await;

    assert_eq!(
        mock.call_count(),
        1,
        "expected exactly 1 upstream call even on failure"
    );

    for result in &results {
        let err = result.as_ref().unwrap().as_ref().unwrap_err();
        assert!(
            matches!(err, DomainError::NxDomain),
            "all waiters should receive NxDomain"
        );
    }
}

#[tokio::test]
async fn test_no_coalescing_for_different_record_types() {
    let mock = Arc::new(DelayedMockResolver::new(50, "1.2.3.4"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let r1 = Arc::clone(&resolver);
    let r2 = Arc::clone(&resolver);

    let (res_a, res_aaaa) = tokio::join!(
        tokio::spawn(async move { r1.resolve(&make_query("example.com", RecordType::A)).await }),
        tokio::spawn(async move {
            r2.resolve(&make_query("example.com", RecordType::AAAA))
                .await
        }),
    );

    assert_eq!(mock.call_count(), 2, "A and AAAA queries must not coalesce");
    assert!(res_a.unwrap().is_ok());
    assert!(res_aaaa.unwrap().is_ok());
}

#[tokio::test]
async fn test_no_coalescing_for_different_domains() {
    let mock = Arc::new(DelayedMockResolver::new(50, "1.2.3.4"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let r1 = Arc::clone(&resolver);
    let r2 = Arc::clone(&resolver);

    let (res_a, res_b) = tokio::join!(
        tokio::spawn(async move {
            r1.resolve(&make_query("a.example.com", RecordType::A))
                .await
        }),
        tokio::spawn(async move {
            r2.resolve(&make_query("b.example.com", RecordType::A))
                .await
        }),
    );

    assert_eq!(mock.call_count(), 2, "different domains must not coalesce");
    assert!(res_a.unwrap().is_ok());
    assert!(res_b.unwrap().is_ok());
}

#[tokio::test]
async fn test_result_cached_after_coalescing() {
    let mock = Arc::new(DelayedMockResolver::new(50, "1.2.3.4"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
    ));

    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move {
                r.resolve(&make_query("cached.example.com", RecordType::A))
                    .await
            })
        })
        .collect();

    join_all(tasks).await;
    assert_eq!(mock.call_count(), 1);

    let result = resolver
        .resolve(&make_query("cached.example.com", RecordType::A))
        .await;

    assert_eq!(
        mock.call_count(),
        1,
        "subsequent query must hit cache, not upstream"
    );
    let res = result.unwrap();
    assert!(res.cache_hit, "subsequent query should be a cache hit");
    assert_eq!(
        res.addresses.as_ref(),
        &["1.2.3.4".parse::<IpAddr>().unwrap()]
    );
}
