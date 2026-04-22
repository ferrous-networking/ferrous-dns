//! Tests ensuring DNS cache key lookups respect RFC 1035 §2.3.3
//! (DNS names are case-insensitive): `Example.COM` and `example.com`
//! must hit the same cache entry.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

fn create_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
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
    })
}

#[test]
fn should_hit_cache_when_query_case_differs_from_insert() {
    let cache = create_cache();

    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("10.0.0.1"),
        300,
        None,
    );

    let hits_before = cache.metrics().hits.load(Ordering::Relaxed);

    // Query 1: mixed case with uppercase TLD.
    let mixed = cache.get(&Arc::from("Example.COM"), &RecordType::A);
    assert!(
        mixed.is_some(),
        "Mixed-case query `Example.COM` must hit the entry inserted as `example.com`"
    );
    match mixed.unwrap().0 {
        CachedData::IpAddresses(entry) => {
            assert_eq!(entry.addresses.len(), 1);
            assert_eq!(entry.addresses[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        }
        other => panic!("Expected IpAddresses, got {:?}", other),
    }

    // Query 2: different case pattern.
    let upper = cache.get(&Arc::from("EXAMPLE.com"), &RecordType::A);
    assert!(
        upper.is_some(),
        "Uppercase query `EXAMPLE.com` must hit the entry inserted as `example.com`"
    );
    match upper.unwrap().0 {
        CachedData::IpAddresses(entry) => {
            assert_eq!(entry.addresses[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        }
        other => panic!("Expected IpAddresses, got {:?}", other),
    }

    let hits_after = cache.metrics().hits.load(Ordering::Relaxed);
    assert!(
        hits_after >= hits_before + 2,
        "Both case-variant queries must increment hits counter; before={hits_before}, after={hits_after}"
    );
}

#[test]
fn should_share_negative_cache_across_case_variants() {
    let cache = create_cache();

    // Insert a negative response under a mixed-case domain.
    cache.insert(
        "BadDomain.COM",
        RecordType::A,
        CachedData::NegativeResponse,
        120,
        None,
    );

    // Query in fully lowercase should still hit the negative cache.
    let result = cache.get(&Arc::from("baddomain.com"), &RecordType::A);
    assert!(
        result.is_some(),
        "Negative cache must be case-insensitive: inserted `BadDomain.COM`, queried `baddomain.com`"
    );

    let (data, _dnssec, _ttl) = result.unwrap();
    assert!(
        matches!(data, CachedData::NegativeResponse),
        "Expected NegativeResponse, got {:?}",
        data
    );

    // Cross-check: a third case variant also hits the same entry.
    let result_mixed = cache.get(&Arc::from("BADDOMAIN.com"), &RecordType::A);
    assert!(
        result_mixed.is_some(),
        "Negative cache hit for yet another case variant `BADDOMAIN.com`"
    );
}

#[test]
fn should_normalize_domain_in_l1_fast_path() {
    let cache = create_cache();

    // Insert via an uppercase domain — L1 cache key must also be lowercased
    // so subsequent queries of any case variant share the L1 entry.
    cache.insert(
        "UPPER.example.com",
        RecordType::A,
        make_ip_data("203.0.113.42"),
        300,
        None,
    );

    // First query: populates/hits L1 via lowercased composite key.
    let first = cache.get(&Arc::from("upper.example.com"), &RecordType::A);
    assert!(
        first.is_some(),
        "Lowercase query must find the entry inserted as UPPER.example.com"
    );
    let hits_after_first = cache.metrics().hits.load(Ordering::Relaxed);

    // Second query (mixed case) must also hit and increment hits.
    let second = cache.get(&Arc::from("Upper.Example.Com"), &RecordType::A);
    assert!(
        second.is_some(),
        "Mixed-case query must hit the same L1/L2 entry"
    );
    match second.unwrap().0 {
        CachedData::IpAddresses(entry) => {
            assert_eq!(
                entry.addresses[0],
                "203.0.113.42".parse::<IpAddr>().unwrap(),
                "Addresses returned must match the originally inserted ones"
            );
        }
        other => panic!("Expected IpAddresses from L1 fast path, got {:?}", other),
    }

    let hits_after_second = cache.metrics().hits.load(Ordering::Relaxed);
    assert!(
        hits_after_second > hits_after_first,
        "Second case-variant query must increment hits counter (L1 or L2 hit); before={hits_after_first}, after={hits_after_second}"
    );
}
