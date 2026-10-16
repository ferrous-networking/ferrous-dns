//! The refresh worker under load: thousands of entries falling due together
//! while clients read them, overwrite them and push the cache past its
//! capacity. Each wait has a deadline, so a deadlock fails the test instead of
//! hanging CI.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, ColdThresholds, DnsCache, DnsCacheConfig, DnsCacheMaintenance,
    EvictionStrategy, RefreshRequest,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const ENTRIES: usize = 20_000;
/// Puts a 300 s entry due a second after it is stored, and its 3600 s
/// renewal 14 s after that, so each entry is renewed once during a test.
const REFRESH_THRESHOLD: f64 = 0.004;

/// Answers at once with a 3600 s TTL, counting the calls.
struct CountingResolver {
    calls: AtomicUsize,
}

#[async_trait]
impl DnsResolver for CountingResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(DnsResolution {
            min_ttl: Some(3600),
            ..DnsResolution::new(vec!["192.0.2.2".parse().unwrap()], false)
        })
    }
}

fn cache(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: REFRESH_THRESHOLD,
        batch_eviction_percentage: 0.1,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 16,
        access_window_secs: u64::MAX,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
        renew_ahead: true,
        retry_lapsed_after_secs: 300,
    }))
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec!["192.0.2.1".parse::<IpAddr>().unwrap()]),
    })
}

/// Wires the cache's repair queue; its timers wait in its inbox until a
/// worker starts on it.
fn wire(cache: &DnsCache) -> mpsc::Receiver<RefreshRequest> {
    let (stale, stale_rx) = mpsc::channel(128);
    cache.set_stale_repairs(stale);
    stale_rx
}

fn start_worker(
    cache: &Arc<DnsCache>,
    resolver: Arc<CountingResolver>,
    stale_rx: mpsc::Receiver<RefreshRequest>,
) {
    let _ticker = coarse_clock::start_clock_ticker();
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(cache),
        resolver,
        None,
        stale_rx,
        ColdThresholds {
            min_hit_rate: 0.0,
            min_frequency: 0,
        },
    );
}

/// Reads random entries from two threads until `stop` is set, overwriting one
/// read in 4096, about the rate a busy resolver stores upstream answers.
fn spawn_clients(
    cache: &Arc<DnsCache>,
    stop: &Arc<AtomicBool>,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..2u64)
        .map(|seed| {
            let cache = Arc::clone(cache);
            let stop = Arc::clone(stop);
            std::thread::spawn(move || {
                let mut i = seed;
                while !stop.load(Ordering::Relaxed) {
                    i = i.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let domain = format!("stress-{}.example", i % ENTRIES as u64);
                    if i % 4096 == 0 {
                        cache.insert(&domain, RecordType::A, address(), 300, None);
                    } else {
                        let _ = cache.get(&domain, &RecordType::A);
                    }
                }
            })
        })
        .collect()
}

async fn wait_for(within: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while !done() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_every_due_entry_is_renewed_under_concurrent_load() {
    let cache = cache(ENTRIES * 2);
    let resolver = Arc::new(CountingResolver {
        calls: AtomicUsize::new(0),
    });
    let receivers = wire(&cache);
    start_worker(&cache, Arc::clone(&resolver), receivers);
    for i in 0..ENTRIES {
        cache.insert(
            &format!("stress-{i}.example"),
            RecordType::A,
            address(),
            300,
            None,
        );
    }
    let stop = Arc::new(AtomicBool::new(false));
    let clients = spawn_clients(&cache, &stop);

    let renewed = wait_for(Duration::from_secs(15), || {
        resolver.calls.load(Ordering::Relaxed) >= ENTRIES
    })
    .await;

    stop.store(true, Ordering::Relaxed);
    for client in clients {
        client.join().unwrap();
    }
    assert!(
        renewed,
        "every due entry must be renewed under load; renewals={}",
        resolver.calls.load(Ordering::Relaxed)
    );
    assert_eq!(
        cache
            .metrics()
            .optimistic_refresh_shed
            .load(Ordering::Relaxed),
        0,
        "no renewal may be given up while the worker keeps up"
    );
}

/// Inserting past capacity and evicting leaves timers whose entry is gone.
/// They must cost no upstream query, and their sweep must not stall renewals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_timers_of_evicted_entries_spend_no_queries() {
    let max_entries = ENTRIES / 4;
    let cache = cache(max_entries);
    let resolver = Arc::new(CountingResolver {
        calls: AtomicUsize::new(0),
    });
    // Everything is inserted and evicted before the worker starts, so no
    // entry can be renewed and then evicted: each renewal is a survivor's.
    let receivers = wire(&cache);
    for i in 0..ENTRIES {
        cache.insert(
            &format!("stress-{i}.example"),
            RecordType::A,
            address(),
            300,
            None,
        );
        if i % max_entries == max_entries - 1 {
            while cache.len() > max_entries / 2 {
                cache.evict_entries();
            }
        }
    }
    let survivors = cache.len();
    start_worker(&cache, Arc::clone(&resolver), receivers);

    tokio::time::sleep(Duration::from_millis(3_000)).await;

    let renewals = resolver.calls.load(Ordering::Relaxed);
    assert!(
        renewals <= survivors,
        "only entries still cached may be renewed: {renewals} renewals, {survivors} cached"
    );
    assert!(
        renewals > 0,
        "the survivors must still be renewed while the orphans are swept"
    );
}
