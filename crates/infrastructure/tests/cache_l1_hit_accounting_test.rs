//! A hit served by the thread-local L1 is still a hit on the record.
//!
//! An address answer is copied into L1 when it is cached, and from then on a
//! lookup on that thread never reaches L2, which holds the counters. L1 hands
//! its hits over in batches, so the name clients ask for most keeps a recent
//! `last_access`, which keeps it inside the refresh access window, and a high
//! `hit_count`, which keeps capacity eviction from picking it first.

use ferrous_dns_application::ports::{CacheEntryQuery, CacheEntrySnapshot};
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

fn cache(max_entries: usize, access_window_secs: u64) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs,
        eviction_sample_size: 16,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec!["192.0.2.7".parse::<IpAddr>().unwrap()]),
    })
}

/// Caches `domain` and serves it `lookups` times from this thread's L1, then
/// once more after the coarse clock has moved on. Returns the clock reading
/// taken just before that last lookup.
fn serve_from_l1(cache: &DnsCache, domain: &str, lookups: u32) -> u64 {
    coarse_clock::tick();
    cache.insert(domain, RecordType::A, address(), 3600, None);
    for _ in 0..lookups {
        assert!(cache.get(domain, &RecordType::A).is_some());
    }
    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    let now = coarse_clock::coarse_now_secs();
    assert!(cache.get(domain, &RecordType::A).is_some());
    now
}

fn listed(cache: &DnsCache, domain: &str) -> Option<CacheEntrySnapshot> {
    cache
        .list_entries(&CacheEntryQuery {
            domain: Some(domain.to_string()),
            ..Default::default()
        })
        .entries
        .into_iter()
        .find(|entry| entry.domain == domain)
}

/// Every lookup L1 serves is counted on the record.
#[test]
fn test_l1_hits_reach_the_record_counters() {
    let cache = cache(100, 7200);
    serve_from_l1(&cache, "l1-counted.example", 50);

    let entry = listed(&cache, "l1-counted.example").expect("entry listed");
    assert!(
        entry.hits >= 50,
        "50 lookups served by L1 must count as hits, got {}",
        entry.hits
    );
}

/// The last lookup L1 served is the record's last access, so with a one
/// second access window a name read every few milliseconds stays inside it.
#[test]
fn test_l1_hits_keep_the_last_access_current() {
    let cache = cache(100, 1);
    let now = serve_from_l1(&cache, "l1-eligible.example", 50);

    let entry = listed(&cache, "l1-eligible.example").expect("entry listed");
    assert!(
        entry.last_access_secs >= now,
        "the last L1 lookup at {now} must be the last access, got {}",
        entry.last_access_secs
    );
}

/// Renewing an entry replaces this thread's L1 copy; the hits that copy had
/// batched must still reach the record.
#[test]
fn test_l1_hits_batched_before_a_renewal_are_counted() {
    let cache = cache(100, 7200);
    coarse_clock::tick();
    cache.insert("renewed.example", RecordType::A, address(), 3600, None);
    for _ in 0..50 {
        assert!(cache.get("renewed.example", &RecordType::A).is_some());
    }
    assert!(cache.refresh_record(
        "renewed.example",
        &RecordType::A,
        Some(3600),
        address(),
        None
    ));
    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    assert!(cache.get("renewed.example", &RecordType::A).is_some());

    let entry = listed(&cache, "renewed.example").expect("entry listed");
    assert!(
        entry.hits >= 51,
        "51 lookups served, {} counted",
        entry.hits
    );
}

/// A batch that fills its `u16` is handed over at once, and none is lost.
#[test]
fn test_l1_batch_that_fills_its_counter_loses_no_hit() {
    let cache = cache(100, 7200);
    coarse_clock::tick();
    cache.insert("busy.example", RecordType::A, address(), 3600, None);
    for _ in 0..70_000 {
        assert!(cache.get("busy.example", &RecordType::A).is_some());
    }
    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();
    assert!(cache.get("busy.example", &RecordType::A).is_some());

    let entry = listed(&cache, "busy.example").expect("entry listed");
    assert_eq!(entry.hits, 70_001);
}

/// A full cache evicts by hit rate, so the name with the most hits, all of
/// them served by L1, must outlive names read three times each.
#[test]
fn test_capacity_eviction_spares_the_hot_l1_name() {
    let cache = cache(10, 7200);
    serve_from_l1(&cache, "l1-hot.example", 50);
    for i in 0..9 {
        let cold = format!("cold-{i}.example");
        // A CNAME never enters L1, so these three lookups are L2 hits.
        cache.insert(
            &cold,
            RecordType::A,
            CachedData::CanonicalName(Arc::from("target.example")),
            3600,
            None,
        );
        for _ in 0..3 {
            assert!(cache.get(&cold, &RecordType::A).is_some());
        }
    }
    assert_eq!(cache.len(), 10);

    cache.evict_entries();

    assert_eq!(cache.len(), 9, "one entry must be evicted");
    assert!(
        listed(&cache, "l1-hot.example").is_some(),
        "the most-hit name must not be the one evicted"
    );
}
