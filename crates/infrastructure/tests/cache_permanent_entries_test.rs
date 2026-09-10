//! Permanent cache entries — the local DNS records preloaded from config.
//!
//! Nothing reloads them once they leave the cache, so they have to survive a
//! `clear()`, and they have to report the TTL they were configured with rather
//! than the distance to their sentinel `u64::MAX` expiry.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;

fn make_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.0,
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
    })
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

fn addresses_of(data: &CachedData) -> Vec<IpAddr> {
    match data {
        CachedData::IpAddresses(entry) => entry.addresses.as_ref().clone(),
        _ => panic!("expected address data"),
    }
}

#[test]
fn test_permanent_entry_reports_its_configured_ttl() {
    let cache = make_cache();
    cache.insert_permanent(
        "nas.home.lan",
        RecordType::A,
        make_ip_data("10.0.0.5"),
        300,
        None,
    );

    let (_, _, remaining) = cache
        .get("nas.home.lan", &RecordType::A)
        .expect("permanent entry must be readable");

    assert_eq!(remaining, Some(300));
}

#[test]
fn test_permanent_entry_ttl_survives_a_second_read_from_l1() {
    let cache = make_cache();
    cache.insert_permanent(
        "printer.home.lan",
        RecordType::A,
        make_ip_data("10.0.0.6"),
        120,
        None,
    );

    // First read promotes into the thread-local L1; the second is served from it.
    let _ = cache.get("printer.home.lan", &RecordType::A);
    let (_, _, remaining) = cache
        .get("printer.home.lan", &RecordType::A)
        .expect("permanent entry must still be readable");

    let remaining = remaining.expect("permanent entry has a TTL");
    assert!(
        (110..=120).contains(&remaining),
        "L1 must not report the sentinel expiry: {remaining}"
    );
}

#[test]
fn test_clear_preserves_permanent_entries() {
    let cache = make_cache();
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

    cache.clear();

    assert!(
        cache.get("example.com", &RecordType::A).is_none(),
        "an upstream answer must not survive a flush"
    );

    let (data, _, remaining) = cache
        .get("nas.home.lan", &RecordType::A)
        .expect("a local DNS record must survive a flush — nothing reloads it");
    assert_eq!(
        addresses_of(&data),
        vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(remaining, Some(300));
    assert!(cache.is_permanent("nas.home.lan", &RecordType::A));
}

#[test]
fn test_is_permanent_distinguishes_the_two_kinds() {
    let cache = make_cache();
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

    assert!(cache.is_permanent("nas.home.lan", &RecordType::A));
    assert!(cache.is_permanent("NAS.HOME.LAN", &RecordType::A));
    assert!(!cache.is_permanent("nas.home.lan", &RecordType::AAAA));
    assert!(!cache.is_permanent("example.com", &RecordType::A));
    assert!(!cache.is_permanent("absent.home.lan", &RecordType::A));
}

#[test]
fn test_removed_permanent_entry_is_no_longer_permanent() {
    let cache = make_cache();
    cache.insert_permanent(
        "nas.home.lan",
        RecordType::A,
        make_ip_data("10.0.0.5"),
        300,
        None,
    );

    assert!(cache.remove("nas.home.lan", &RecordType::A));

    assert!(!cache.is_permanent("nas.home.lan", &RecordType::A));
    cache.clear();
    assert!(
        cache.get("nas.home.lan", &RecordType::A).is_none(),
        "a removed entry must not come back through clear()"
    );
}
