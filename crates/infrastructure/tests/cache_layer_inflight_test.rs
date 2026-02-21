use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use futures::future::join_all;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct FailingResolver {
    error: Mutex<Option<DomainError>>,
}

impl FailingResolver {
    fn new() -> Self {
        Self {
            error: Mutex::new(Some(DomainError::NxDomain)),
        }
    }
}

#[async_trait]
impl DnsResolver for FailingResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = self
            .error
            .lock()
            .unwrap()
            .take()
            .unwrap_or(DomainError::NxDomain);
        Err(err)
    }
}

fn make_cache() -> Arc<dyn DnsCacheAccess> {
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
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    }))
}

fn make_query(domain: &str) -> DnsQuery {
    DnsQuery {
        domain: Arc::from(domain),
        record_type: RecordType::A,
    }
}

#[tokio::test]
async fn test_inflight_map_empty_after_leader_error() {
    let resolver = Arc::new(CachedResolver::new(
        Arc::new(FailingResolver::new()) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
    ));

    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve(&make_query("error.example")).await })
        })
        .collect();

    let results: Vec<_> = join_all(tasks).await;

    for result in &results {
        let inner = result.as_ref().unwrap();
        assert!(
            inner.is_err(),
            "all followers should receive error or NxDomain"
        );
    }
}

#[tokio::test]
async fn test_follower_receives_error_on_leader_failure_without_hanging() {
    let resolver = Arc::new(CachedResolver::new(
        Arc::new(FailingResolver::new()) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
    ));

    let r1 = Arc::clone(&resolver);
    let r2 = Arc::clone(&resolver);

    let (res1, res2) = tokio::join!(
        tokio::spawn(async move { r1.resolve(&make_query("timeout-test.example")).await }),
        tokio::spawn(async move { r2.resolve(&make_query("timeout-test.example")).await }),
    );

    assert!(res1.unwrap().is_err());
    assert!(res2.unwrap().is_err());
}
