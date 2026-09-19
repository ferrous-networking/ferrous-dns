//! The eviction branch that does not score candidates.
//!
//! `evict_entries` falls back to it whenever the cache already sits at or below
//! half of `max_entries` — which happens routinely when compaction drops a burst
//! of short-TTL entries between the moment `insert` raises `eviction_pending`
//! and the moment the maintenance cycle consumes it.
//!
//! That branch used to remove a key while still holding the dashmap shard guard
//! it was iterating, so it deadlocked on its own shard and took the whole cache
//! refresh down with it (issue #228). Every test here runs the eviction on a
//! separate thread behind a timeout, so a reintroduced deadlock fails the suite
//! instead of hanging it.

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

/// `max_entries` is deliberately small: the fallback branch is the one taken
/// while `len <= max_entries / 2`, and `batch_eviction_percentage` of 0.2 makes
/// a cycle evict exactly one entry.
fn make_cache(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 0.0,
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

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
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
fn test_fallback_eviction_returns_instead_of_deadlocking() {
    let cache = make_cache(8);
    cache.insert(
        "a.local.test",
        RecordType::A,
        make_ip_data("192.0.2.1"),
        300,
        None,
    );

    // len (1) <= max_entries / 2 (4), so `evict_entries` takes the fallback.
    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    assert_eq!(cache.size(), 0, "the single entry should have been evicted");
    assert_eq!(
        cache.metrics().evictions.load(Ordering::Relaxed),
        1,
        "the eviction should be counted exactly once"
    );
}

#[test]
fn test_fallback_eviction_keeps_permanent_entries() {
    let cache = make_cache(8);
    cache.insert_permanent(
        "nas.home.lan",
        RecordType::A,
        make_ip_data("10.0.0.5"),
        300,
        None,
    );
    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("93.184.216.34"),
        300,
        None,
    );

    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    // Permanent entries are local DNS records loaded from config: nothing
    // reloads them, and dropping one here would leave `permanent_records`
    // claiming a name the backing map no longer holds.
    assert_eq!(
        cache.size(),
        1,
        "only the non-permanent entry should have been evicted"
    );
    assert!(cache.is_permanent("nas.home.lan", &RecordType::A));
    assert!(
        cache.get("nas.home.lan", &RecordType::A).is_some(),
        "the permanent entry must still be readable"
    );
}

#[test]
fn test_fallback_eviction_terminates_when_every_entry_is_permanent() {
    let cache = make_cache(8);
    for (domain, ip) in [
        ("nas.home.lan", "10.0.0.5"),
        ("printer.home.lan", "10.0.0.6"),
    ] {
        cache.insert_permanent(domain, RecordType::A, make_ip_data(ip), 300, None);
    }

    let evicting = Arc::clone(&cache);
    run_with_deadlock_guard("evict_entries", move || evicting.evict_entries());

    assert_eq!(cache.size(), 2, "permanent entries are never evicted");
    assert_eq!(
        cache.metrics().evictions.load(Ordering::Relaxed),
        0,
        "nothing was removed, so nothing should be counted"
    );
}
