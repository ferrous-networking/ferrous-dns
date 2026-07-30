//! The bloom filter is an authoritative negative gate on `DnsCache::get`, so a
//! rotation that drops a live key turns a valid cached answer into an upstream
//! query. These tests pin the re-seeding behaviour that prevents that.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::{CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
use std::sync::Arc;

fn create_cache(min_ttl: u32) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 8,
        access_window_secs: 43_200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl,
        max_ttl: 86_400,
    })
}

/// `CanonicalName` never lands in the thread-local L1, which is consulted
/// before the bloom — so `get` here really exercises the bloom gate.
fn make_cname_data(name: &str) -> CachedData {
    CachedData::CanonicalName(Arc::from(name))
}

#[test]
fn unread_live_entry_survives_repeated_rotations() {
    let cache = create_cache(300);
    cache.insert(
        "example.com",
        RecordType::A,
        make_cname_data("cdn.example.net"),
        3600,
        None,
    );

    for _ in 0..5 {
        cache.rotate_bloom();
    }

    assert_eq!(
        cache.get_remaining_ttl("example.com", &RecordType::A),
        Some(3600),
        "record must still be fresh"
    );
    assert!(
        cache.get("example.com", &RecordType::A).is_some(),
        "a live record must stay visible even when never read between rotations"
    );
}

#[test]
fn refresh_record_rearms_the_bloom() {
    let cache = create_cache(300);
    cache.insert(
        "example.com",
        RecordType::A,
        make_cname_data("cdn.example.net"),
        3600,
        None,
    );

    assert!(cache.refresh_record(
        "example.com",
        &RecordType::A,
        Some(3600),
        make_cname_data("cdn2.example.net"),
        None,
    ));

    cache.rotate_bloom();
    cache.rotate_bloom();

    assert!(
        cache.get("example.com", &RecordType::A).is_some(),
        "an entry renewed by the optimistic refresh job must stay visible"
    );
}

#[test]
fn rotation_does_not_reseed_expired_entries() {
    let cache = create_cache(0);
    cache.insert(
        "expired.com",
        RecordType::A,
        make_cname_data("gone.example.net"),
        0,
        None,
    );
    cache.insert(
        "alive.com",
        RecordType::A,
        make_cname_data("cdn.example.net"),
        3600,
        None,
    );

    assert_eq!(
        cache.rotate_bloom(),
        1,
        "only the live entry should be re-seeded"
    );

    cache.rotate_bloom();

    assert!(cache.get("alive.com", &RecordType::A).is_some());
    assert!(cache.get("expired.com", &RecordType::A).is_none());
}

#[test]
fn rotation_reseeds_permanent_entries() {
    let cache = create_cache(300);
    cache.insert_permanent(
        "printer.lan",
        RecordType::A,
        make_cname_data("printer.local"),
        None,
    );

    cache.rotate_bloom();
    cache.rotate_bloom();

    assert!(
        cache.get("printer.lan", &RecordType::A).is_some(),
        "permanent (local DNS) records must never age out of the bloom"
    );
}
