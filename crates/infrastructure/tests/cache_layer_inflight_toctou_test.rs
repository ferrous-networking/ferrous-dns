//! Phase 5: regression tests for the TOCTOU race in the coalescing
//! leader-election path.
//!
//! Before the fix, `resolve` performed a second `check_cache` + `inflight.remove`
//! between `register_or_join_inflight` and `resolve_as_leader`. That sequence
//! could:
//!   1. orphan followers that subscribed between the two ops, forcing them
//!      to fall back through the watch-channel-closed path; and
//!   2. still dispatch a redundant upstream call when an elected leader's
//!      own cached data was discovered only after election.
//!
//! The fix moves the second cache check INSIDE `resolve_as_leader`, where
//! the leader already holds an `InflightLeaderGuard` and can wake followers
//! via the same watch channel used by the upstream-success branch.
//!
//! These tests simulate the cache-populated-mid-flight scenario by wrapping
//! the real cache in an interceptor that suppresses the *first* `get()` for
//! a target key (forcing the first `check_cache` in `resolve` to miss), and
//! then delegates to the inner cache for every subsequent call. That pins
//! the race window to the second (in-leader) check, which the Phase 5 fix
//! is responsible for handling.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheAccess, DnsCacheConfig, DnssecStatus,
    EvictionStrategy, NegativeQueryTracker,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Resolver that records how many times it was invoked. Used as a
/// sentinel: after the fix, a leader that finds a cached value during
/// its in-flight check must NOT reach the upstream mock — the counter
/// should stay at zero.
struct CountingMockResolver {
    call_count: Arc<AtomicUsize>,
    response: DnsResolution,
}

impl CountingMockResolver {
    fn new(addr: &str) -> Self {
        let ip: IpAddr = addr.parse().unwrap();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            response: DnsResolution::new(vec![ip], false),
        }
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for CountingMockResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        // A small delay makes any accidental leader race more visible if
        // it ever returns — with the fix in place, we should never await here.
        tokio::time::sleep(Duration::from_millis(25)).await;
        Ok(self.response.clone())
    }
}

/// Cache wrapper that suppresses the first `get()` call for each
/// `(domain, record_type)` pair, forcing the caller to miss once before
/// every subsequent call delegates to the inner cache.
///
/// This is how the tests synthesize the TOCTOU window: the first
/// `check_cache` in `CachedResolver::resolve` is guaranteed to miss,
/// then by the time the leader reaches its in-flight `check_cache`
/// (moved there by Phase 5), the inner cache has already been populated
/// by the test harness, so the leader short-circuits without invoking
/// `inner.resolve`.
struct FirstMissOnceCache {
    inner: Arc<dyn DnsCacheAccess>,
    // Number of times `get()` has returned a forced-miss. Kept as a shared
    // atomic so the test can assert the suppression actually triggered.
    suppressed_calls: Arc<AtomicUsize>,
    // How many forced misses to issue before delegating. `1` means the
    // very first `get()` misses, then every subsequent one delegates.
    force_miss_count: usize,
}

impl FirstMissOnceCache {
    fn new(inner: Arc<dyn DnsCacheAccess>, force_miss_count: usize) -> Self {
        Self {
            inner,
            suppressed_calls: Arc::new(AtomicUsize::new(0)),
            force_miss_count,
        }
    }

    fn suppressed_calls(&self) -> usize {
        self.suppressed_calls.load(Ordering::SeqCst)
    }
}

impl DnsCacheAccess for FirstMissOnceCache {
    fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<DnssecStatus>, Option<u32>)> {
        let prev = self.suppressed_calls.load(Ordering::SeqCst);
        if prev < self.force_miss_count {
            self.suppressed_calls.fetch_add(1, Ordering::SeqCst);
            return None;
        }
        self.inner.get(domain, record_type)
    }

    fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<DnssecStatus>,
    ) {
        self.inner
            .insert(domain, record_type, data, ttl, dnssec_status);
    }
}

fn make_inner_cache() -> Arc<dyn DnsCacheAccess> {
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

fn make_query(domain: &str, record_type: RecordType) -> DnsQuery {
    DnsQuery {
        domain: Arc::from(domain),
        record_type,
    }
}

fn preload(cache: &dyn DnsCacheAccess, domain: &str, record_type: RecordType, addr: &str) {
    let ip: IpAddr = addr.parse().unwrap();
    cache.insert(
        domain,
        record_type,
        CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![ip]),
        }),
        300,
        Some(DnssecStatus::Insecure),
    );
}

/// Scenario: the leader is elected and its in-flight `check_cache` now
/// finds the requested entry (populated concurrently by another code
/// path). The leader must short-circuit and NEVER call `inner.resolve`.
///
/// Setup: `FirstMissOnceCache` with `force_miss_count = 1` makes the
/// first `check_cache` inside `resolve` miss. The inner cache is then
/// pre-populated BEFORE we spawn the leader, so when the leader reaches
/// its in-flight `check_cache` it delegates and hits. Expectation:
/// upstream call count stays at zero and the leader returns the cached
/// value.
#[tokio::test]
async fn should_not_make_second_upstream_call_when_cache_filled_between_leader_election_and_resolve(
) {
    let mock = Arc::new(CountingMockResolver::new("10.0.0.1"));
    let inner_cache = make_inner_cache();
    let intercept = Arc::new(FirstMissOnceCache::new(Arc::clone(&inner_cache), 1));

    // Pre-populate the *inner* cache so the in-leader check delegates
    // to a populated store; the interceptor's first-call miss still
    // guarantees the outer (in-`resolve`) check misses first.
    preload(
        inner_cache.as_ref(),
        "example.com",
        RecordType::A,
        "10.0.0.1",
    );

    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        Arc::clone(&intercept) as Arc<dyn DnsCacheAccess>,
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    let result = resolver
        .resolve(&make_query("example.com", RecordType::A))
        .await
        .expect("cached value must be returned without upstream");

    assert_eq!(
        mock.call_count(),
        0,
        "leader must NOT call upstream when its in-flight cache check hits"
    );
    assert_eq!(
        intercept.suppressed_calls(),
        1,
        "interceptor must have forced exactly one miss (the first resolve check)"
    );
    assert_eq!(
        result.addresses.as_ref(),
        &["10.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert!(
        result.cache_hit,
        "leader-short-circuit path must surface the cache_hit flag from the cached value"
    );
}

/// Scenario: a real follower subscribed to an in-flight leader must be
/// woken with the cached payload when the leader short-circuits on its
/// in-flight cache check, instead of being orphaned (as the old
/// `inflight.remove(&key)` shortcut would have done, forcing followers
/// to fall back through the watch-channel-closed path and trigger a
/// redundant resolve).
///
/// We need a cache `get` hook that blocks the leader's in-flight check
/// (its 2nd `get` for the target key) until a follower has joined.
/// `DnsCacheAccess::get` is synchronous — we park it on a
/// `std::sync::mpsc::Receiver::recv()`, which blocks the tokio worker
/// thread but is safe here because:
///   1. the multi-thread runtime keeps other workers free to drive the
///      follower forward, and
///   2. the test always unblocks the gate via a channel send before any
///      timeout could trigger.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn should_wake_followers_with_cached_result_when_leader_finds_cache_hit() {
    use std::sync::mpsc;
    use std::sync::Mutex;

    struct DeferredGetCache {
        inner: Arc<dyn DnsCacheAccess>,
        target_domain: String,
        target_type: RecordType,
        hits: AtomicUsize,
        // Sender side signalled by the test to unblock the 2nd `get`.
        gate_rx: Mutex<Option<mpsc::Receiver<()>>>,
        // Notifies the test that the leader is parked at the in-flight
        // cache check (hit index == 1). Exposed via a `mpsc::Sender`.
        checkpoint_tx: mpsc::Sender<()>,
    }

    impl DnsCacheAccess for DeferredGetCache {
        fn get(
            &self,
            domain: &str,
            record_type: &RecordType,
        ) -> Option<(CachedData, Option<DnssecStatus>, Option<u32>)> {
            let is_target = domain == self.target_domain && *record_type == self.target_type;
            if !is_target {
                return self.inner.get(domain, record_type);
            }
            let hit_index = self.hits.fetch_add(1, Ordering::SeqCst);
            match hit_index {
                // 1st hit: leader's `resolve` first check — force miss.
                0 => None,
                // 2nd hit: leader's in-flight `resolve_as_leader` check.
                // Park here until the test opens the gate, which only
                // happens after the follower has joined on the inflight
                // entry (so the leader's subsequent `wake_followers_with_cached`
                // actually has a follower to wake).
                1 => {
                    let _ = self.checkpoint_tx.send(());
                    let rx = self
                        .gate_rx
                        .lock()
                        .unwrap()
                        .take()
                        .expect("gate receiver was consumed twice — test bug");
                    let _ = rx.recv();
                    self.inner.get(domain, record_type)
                }
                // 3rd hit: follower's `resolve` first check — force miss
                // so the follower proceeds into `register_or_join_inflight`
                // and SUBSCRIBES to the inflight entry as a follower.
                2 => None,
                // 4th+ hits: all subsequent calls (e.g. the follower's
                // fallback `check_cache` on a watch-closed path, should
                // the wake-up ever regress) delegate to the inner cache.
                _ => self.inner.get(domain, record_type),
            }
        }

        fn insert(
            &self,
            domain: &str,
            record_type: RecordType,
            data: CachedData,
            ttl: u32,
            dnssec_status: Option<DnssecStatus>,
        ) {
            self.inner
                .insert(domain, record_type, data, ttl, dnssec_status);
        }
    }

    let inner_cache = make_inner_cache();
    preload(
        inner_cache.as_ref(),
        "race.example",
        RecordType::A,
        "10.0.0.3",
    );

    let (checkpoint_tx, checkpoint_rx) = mpsc::channel::<()>();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();

    let deferred = Arc::new(DeferredGetCache {
        inner: Arc::clone(&inner_cache),
        target_domain: "race.example".to_string(),
        target_type: RecordType::A,
        hits: AtomicUsize::new(0),
        gate_rx: Mutex::new(Some(gate_rx)),
        checkpoint_tx,
    });

    let mock = Arc::new(CountingMockResolver::new("10.0.0.3"));
    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        Arc::clone(&deferred) as Arc<dyn DnsCacheAccess>,
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    // Leader task: will block inside the in-flight check on `gate_rx`.
    let leader_resolver = Arc::clone(&resolver);
    let leader = tokio::spawn(async move {
        leader_resolver
            .resolve(&make_query("race.example", RecordType::A))
            .await
    });

    // Wait until the leader is parked at the in-flight cache check.
    // Running this on a `spawn_blocking` so we don't starve the runtime
    // while the std mpsc blocks.
    tokio::task::spawn_blocking(move || {
        checkpoint_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("leader never reached in-flight check point");
    })
    .await
    .expect("checkpoint-waiter task join failed");

    // Spawn follower AFTER the leader is parked. The interceptor's 3rd
    // `get` call (the follower's first `check_cache`) is forced to miss,
    // so the follower subscribes as a real follower on the leader's
    // inflight entry — which is exactly the configuration
    // `wake_followers_with_cached` is designed to serve.
    let follower_resolver = Arc::clone(&resolver);
    let follower = tokio::spawn(async move {
        follower_resolver
            .resolve(&make_query("race.example", RecordType::A))
            .await
    });

    // Give the follower a beat to reach `resolve_as_follower` and park
    // on `rx.changed()`. We can't directly observe this internal state;
    // a short sleep is the pragmatic coordination.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Release the leader so it takes the in-flight cache shortcut and
    // drives `wake_followers_with_cached`.
    gate_tx
        .send(())
        .expect("gate receiver dropped before test released leader");

    let leader_res = leader
        .await
        .expect("leader task join failed")
        .expect("leader must succeed via in-flight cache shortcut");
    let follower_res = follower
        .await
        .expect("follower task join failed")
        .expect("follower must succeed");

    let expected: IpAddr = "10.0.0.3".parse().unwrap();
    assert_eq!(leader_res.addresses.as_ref(), &[expected]);
    assert_eq!(follower_res.addresses.as_ref(), &[expected]);
    assert!(leader_res.cache_hit);
    assert!(follower_res.cache_hit);
    assert_eq!(
        mock.call_count(),
        0,
        "no upstream calls — both paths served via cache"
    );
}
