//! Capacity eviction must never remove a key while it still holds the dashmap
//! shard guard it is iterating.
//!
//! An unscored eviction branch, since removed (#324), once did exactly that: it
//! deadlocked on its own shard and took the whole cache refresh down with it
//! (issue #228). The scored pass walks the map the same way, so every test here
//! runs the eviction on a separate thread behind a timeout, and a reintroduced
//! deadlock fails the suite instead of hanging it.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const GUARD_TIMEOUT: Duration = Duration::from_secs(5);

/// `max_entries` is deliberately small: a pass only runs on a full cache, and a
/// `batch_eviction_percentage` of 0.2 makes one at capacity evict exactly one
/// entry.
fn make_cache(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries,
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

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses::new(Arc::new(vec![addr])))
}

fn insert_names(cache: &DnsCache, count: usize) {
    for i in 0..count {
        cache.insert(
            &format!("host-{i}.example"),
            RecordType::A,
            make_ip_data(&format!("192.0.2.{}", i + 1)),
            300,
            None,
        );
    }
}

/// Runs `f` on its own thread and fails if it has not returned within
/// [`GUARD_TIMEOUT`]. The failure mode under test is a deadlock, not a panic, so
/// calling the code directly would hang the test binary instead of reporting.
fn run_with_deadlock_guard<F>(label: &str, f: F)
where
    F: FnOnce() + Send + 'static,
{
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        f();
        let _ = done_tx.send(());
    });

    assert!(
        done_rx.recv_timeout(GUARD_TIMEOUT).is_ok(),
        "{label} did not return within {GUARD_TIMEOUT:?}: the eviction branch is deadlocked on its own shard (#228)"
    );
}

#[test]
fn test_eviction_returns_instead_of_deadlocking() {
    let cache = make_cache(8);
    insert_names(&cache, 8);

    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    assert_eq!(cache.len(), 7, "one entry should have been evicted");
    assert_eq!(
        cache.metrics().evictions.load(Ordering::Relaxed),
        1,
        "the eviction should be counted exactly once"
    );
}

#[test]
fn test_eviction_keeps_permanent_entries() {
    let cache = make_cache(8);
    cache.insert_permanent("nas.home.lan", RecordType::A, make_ip_data("10.0.0.5"), 300);
    insert_names(&cache, 7);

    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    // Permanent entries are local DNS records loaded from config: nothing
    // reloads them, and dropping one here would leave `permanent_records`
    // claiming a name the backing map no longer holds.
    assert_eq!(
        cache.len(),
        7,
        "one non-permanent entry should have been evicted"
    );
    assert!(cache.is_permanent("nas.home.lan", &RecordType::A));
    assert!(
        cache.get("nas.home.lan", &RecordType::A).is_some(),
        "the permanent entry must still be readable"
    );
}

#[test]
fn test_eviction_terminates_when_every_entry_is_permanent() {
    let cache = make_cache(8);
    for i in 0..8 {
        cache.insert_permanent(
            &format!("device-{i}.home.lan"),
            RecordType::A,
            make_ip_data(&format!("10.0.0.{}", i + 5)),
            300,
        );
    }

    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    assert_eq!(cache.len(), 8, "permanent entries are never evicted");
    assert_eq!(
        cache.metrics().evictions.load(Ordering::Relaxed),
        0,
        "nothing was removed, so nothing should be counted"
    );
}
