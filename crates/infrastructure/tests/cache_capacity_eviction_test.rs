//! Capacity eviction (issue #324): what one `evict_entries` pass removes, and
//! which entries it can pick.
//!
//! A pass removes what the cache holds past `max_entries` plus
//! `batch_eviction_percentage` of it as headroom, so a cache that took in names
//! faster than one batch per pass still ends the pass below capacity. Its
//! candidates come from a window that starts where the previous pass stopped,
//! so an entry is a candidate wherever its key lands in the map, not only when
//! it sits in the first shards.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::{CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// LFU with no minimum frequency scores an entry by its hit count alone, so a
/// name with no hits is always the coldest candidate in a window.
fn cache(max_entries: usize, eviction_sample_size: usize) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::LFU,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
        renew_ahead: true,
        retry_lapsed_after_secs: 300,
    })
}

/// A CNAME never enters L1, so every `get` is an L2 hit on the record.
fn insert(cache: &DnsCache, domain: &str) {
    cache.insert(
        domain,
        RecordType::CNAME,
        CachedData::CanonicalName(Arc::from("target.example")),
        3600,
        None,
    );
}

fn heat(cache: &DnsCache, domain: &str) {
    for _ in 0..5 {
        assert!(cache.get(domain, &RecordType::CNAME).is_some());
    }
}

/// Unlike `get`, `get_ttl` records no hit, so probing leaves the scores alone.
fn is_cached(cache: &DnsCache, domain: &str) -> bool {
    cache.get_ttl(domain, &RecordType::CNAME).is_some()
}

#[test]
fn test_pass_brings_an_overfull_cache_below_capacity() {
    let cache = cache(100, 8);
    for i in 0..250 {
        insert(&cache, &format!("burst-{i}.example"));
    }

    cache.evict_entries();

    assert_eq!(
        cache.len(),
        90,
        "one pass must remove the 150 past capacity plus the 10% headroom"
    );
    assert_eq!(cache.metrics().evictions.load(Ordering::Relaxed), 160);
    assert_eq!(cache.metrics().batch_evictions.load(Ordering::Relaxed), 1);
}

/// Each pass scores a window of three entries and removes the coldest. Every
/// name takes a turn as the only cold one; whichever hot name a pass removes
/// instead is put back, so the next pass finds the cache full again.
#[test]
fn test_cold_entry_is_evicted_wherever_its_key_lands() {
    const NAMES: usize = 10;
    // A lap of the map takes four windows of three; twice the names leaves
    // room for positions shifting as evicted names are put back.
    const PASSES: usize = 2 * NAMES;
    let name = |i: usize| format!("ring-{i}.example");

    let mut never_evicted = Vec::new();
    for cold in 0..NAMES {
        let cache = cache(NAMES, 3);
        for i in 0..NAMES {
            insert(&cache, &name(i));
            if i != cold {
                heat(&cache, &name(i));
            }
        }

        let mut evicted = false;
        for _ in 0..PASSES {
            cache.evict_entries();
            if !is_cached(&cache, &name(cold)) {
                evicted = true;
                break;
            }
            for hot in (0..NAMES).filter(|&i| i != cold) {
                if !is_cached(&cache, &name(hot)) {
                    insert(&cache, &name(hot));
                    heat(&cache, &name(hot));
                }
            }
        }
        if !evicted {
            never_evicted.push(name(cold));
        }
    }

    assert!(
        never_evicted.is_empty(),
        "these names had no hits and still outlived {PASSES} passes, \
         while hot names were evicted in their place: {never_evicted:?}"
    );
}

/// Expiry timers can empty the cache between the worker's capacity check and
/// the pass it starts; the pass then has nothing to make room for.
#[test]
fn test_pass_on_a_cache_below_capacity_evicts_nothing() {
    let cache = cache(8, 8);
    for i in 0..7 {
        insert(&cache, &format!("calm-{i}.example"));
    }

    cache.evict_entries();

    assert_eq!(cache.len(), 7, "a cache below capacity keeps every entry");
    assert_eq!(cache.metrics().evictions.load(Ordering::Relaxed), 0);
    assert_eq!(cache.metrics().batch_evictions.load(Ordering::Relaxed), 0);
}
