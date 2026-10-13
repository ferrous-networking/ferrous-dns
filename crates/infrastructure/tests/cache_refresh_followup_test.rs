//! What a renewal that did not renew the entry leaves behind: at most one
//! more attempt, and never a loop of them.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, DnsCacheMaintenance, EvictionStrategy,
    RefreshPriority, RefreshSenders, TimerInbox,
};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// The shipped defaults where they matter: a 2 h access window and
/// `cache_min_ttl = 0`.
fn cache(refresh_threshold: f64) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 200,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7_200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec!["192.0.2.1".parse::<IpAddr>().unwrap()]),
    })
}

fn start_worker(cache: &Arc<DnsCache>, resolver: Arc<dyn DnsResolver>) {
    let _ticker = coarse_clock::start_clock_ticker();
    let (stale, stale_rx) = mpsc::channel(128);
    let timers = Arc::new(TimerInbox::new(4_096));
    cache.set_refresh_senders(RefreshSenders {
        stale,
        schedule: Some(Arc::clone(&timers)),
    });
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(cache),
        resolver,
        None,
        stale_rx,
        Some(timers),
        RefreshPriority {
            min_hit_rate: 0.0,
            min_frequency: 0,
        },
    );
}

/// Answers every query with one address and a fixed TTL, recording the
/// coarse second of each call.
struct FixedTtlResolver {
    ttl: u32,
    calls: Mutex<Vec<u64>>,
}

impl FixedTtlResolver {
    fn new(ttl: u32) -> Arc<Self> {
        Arc::new(Self {
            ttl,
            calls: Mutex::new(Vec::new()),
        })
    }

    /// Seconds after `since` of each call so far.
    fn calls_since(&self, since: u64) -> Vec<u64> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|at| at - since)
            .collect()
    }
}

#[async_trait]
impl DnsResolver for FixedTtlResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls
            .lock()
            .unwrap()
            .push(coarse_clock::coarse_now_secs());
        Ok(DnsResolution {
            min_ttl: Some(self.ttl),
            ..DnsResolution::new(vec!["192.0.2.2".parse().unwrap()], false)
        })
    }
}

async fn wait_until(within: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while !done() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// An upstream that answers TTL 0 must not keep the worker querying it every
/// second once the entry expires, with no client asking.
#[tokio::test]
async fn test_ttl_zero_answers_do_not_requery_upstream_every_second() {
    let cache = cache(0.5);
    let resolver = FixedTtlResolver::new(0);
    start_worker(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    // Due at +2, expires at +4, stale grace ends at +8.
    cache.insert("zero.example", RecordType::A, address(), 4, None);

    tokio::time::sleep(Duration::from_millis(9_500)).await;

    let calls = resolver.calls_since(inserted);
    assert!(
        calls.len() <= 2,
        "the renewal and one more attempt at most; got calls at {calls:?}"
    );
}

/// Compaction must leave alone an entry whose declined renewal already has
/// its one more attempt pending.
#[tokio::test]
async fn test_compaction_does_not_requery_a_declined_renewal() {
    let cache = cache(0.5);
    let resolver = FixedTtlResolver::new(1);
    start_worker(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    // Due at +5 with 5 s left; the upstream offers 1 s, so it is declined.
    cache.insert("declined.example", RecordType::A, address(), 10, None);

    assert!(
        wait_until(Duration::from_secs(8), || !resolver
            .calls_since(inserted)
            .is_empty())
        .await
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    cache.compact();
    let requeried = wait_until(Duration::from_millis(2_500), || {
        resolver.calls_since(inserted).len() >= 2
    })
    .await;

    assert!(
        !requeried,
        "compaction re-queried a declined renewal; calls at {:?}",
        resolver.calls_since(inserted)
    );
}
