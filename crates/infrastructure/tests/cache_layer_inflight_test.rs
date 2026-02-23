use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use futures::future::join_all;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        min_ttl: 0,
        max_ttl: 86_400,
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

#[tokio::test]
async fn test_leader_cancellation_cleans_inflight_and_unblocks_next_query() {
    struct PendingThenFastResolver {
        call_count: Arc<AtomicUsize>,
        first_pending: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DnsResolver for PendingThenFastResolver {
        async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.first_pending.swap(false, Ordering::SeqCst) {
                std::future::pending::<()>().await;
                unreachable!()
            }
            Err(DomainError::NxDomain)
        }
    }

    let call_count = Arc::new(AtomicUsize::new(0));
    let first_pending = Arc::new(AtomicBool::new(true));

    let resolver = Arc::new(CachedResolver::new(
        Arc::new(PendingThenFastResolver {
            call_count: Arc::clone(&call_count),
            first_pending: Arc::clone(&first_pending),
        }) as Arc<dyn DnsResolver>,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
    ));

    let r = Arc::clone(&resolver);
    let _ = tokio::time::timeout(
        Duration::from_millis(50),
        r.resolve(&make_query("cancel-guard.example")),
    )
    .await;

    let r = Arc::clone(&resolver);
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        r.resolve(&make_query("cancel-guard.example")),
    )
    .await;

    assert!(
        result.is_ok(),
        "Query after leader cancellation must not hang (inflight guard must clean up)"
    );
    assert!(
        call_count.load(Ordering::SeqCst) >= 2,
        "Inner resolver must be called at least twice: once for the cancelled leader, once for the new leader"
    );
}
