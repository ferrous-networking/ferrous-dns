//! Regression tests for the coalescing leader's cache check.
//!
//! `CachedResolver::resolve` does not probe the cache itself — callers probe
//! with `try_cache` first — so the only check runs inside `resolve_as_leader`,
//! after the leader holds its `InflightLeaderGuard`. A cache filled between the
//! caller's probe and that check (by another leader, or a refresh) must answer
//! the leader without an upstream call, and must reach any followers through
//! the same watch channel the upstream-success branch uses, rather than
//! orphaning them.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, CachedDnssecStatus, DnsCache, DnsCacheAccess, DnsCacheConfig,
    EvictionStrategy, LocalRecordStatus,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Resolver that records how many times it was invoked: a leader that finds a
/// cached value must never reach it.
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

fn make_inner_cache() -> Arc<dyn DnsCacheAccess> {
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
        Some(CachedDnssecStatus::Insecure),
        false,
    );
}

/// The entry was filled after the caller's own probe: the leader's in-flight
/// check must find it and never call `inner.resolve`.
#[tokio::test]
async fn leader_answers_from_a_cache_filled_after_the_callers_probe() {
    let mock = Arc::new(CountingMockResolver::new("10.0.0.1"));
    let cache = make_inner_cache();
    preload(cache.as_ref(), "example.com", RecordType::A, "10.0.0.1");

    let resolver = Arc::new(CachedResolver::new(
        Arc::clone(&mock) as Arc<dyn DnsResolver>,
        cache,
        300,
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
/// We need a cache `get` hook that blocks the leader's in-flight check (the
/// first `get` for the target key) until a follower has joined.
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
        // Sender side signalled by the test to unblock the leader's `get`.
        gate_rx: Mutex<Option<mpsc::Receiver<()>>>,
        // Notifies the test that the leader is parked at the in-flight
        // cache check. Exposed via a `mpsc::Sender`.
        checkpoint_tx: mpsc::Sender<()>,
    }

    impl DnsCacheAccess for DeferredGetCache {
        fn get(
            &self,
            domain: &str,
            record_type: &RecordType,
        ) -> Option<(CachedData, Option<CachedDnssecStatus>, Option<u32>, bool)> {
            let is_target = domain == self.target_domain && *record_type == self.target_type;
            if !is_target {
                return self.inner.get(domain, record_type);
            }
            let hit_index = self.hits.fetch_add(1, Ordering::SeqCst);
            match hit_index {
                // The leader's in-flight `resolve_as_leader` check. Park here
                // until the test opens the gate, which only happens after the
                // follower has joined on the inflight entry (so the leader's
                // publish actually has a follower to wake).
                0 => {
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
                // Any later call (the follower's fallback `check_cache` on a
                // watch-closed path, should the wake-up ever regress)
                // delegates to the inner cache.
                _ => self.inner.get(domain, record_type),
            }
        }

        fn local_record_status(&self, domain: &str, record_type: &RecordType) -> LocalRecordStatus {
            self.inner.local_record_status(domain, record_type)
        }

        fn insert(
            &self,
            domain: &str,
            record_type: RecordType,
            data: CachedData,
            ttl: u32,
            dnssec_status: Option<CachedDnssecStatus>,
            local_dns: bool,
        ) {
            self.inner
                .insert(domain, record_type, data, ttl, dnssec_status, local_dns);
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

    // Spawn follower AFTER the leader is parked: `resolve` does not probe the
    // cache, so the follower subscribes straight to the leader's inflight
    // entry — exactly the configuration the leader's publish must serve.
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
