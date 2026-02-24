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
        cname_chain: Arc::from(vec![]),
    })
}

#[test]
fn test_ttl_zero_clamped_to_minimum() {
    let cache = make_cache();
    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        0,
        None,
    );
    let ttl = cache.get_ttl("example.com", &RecordType::A);
    assert_eq!(ttl, Some(1), "TTL 0 should be clamped to MIN (1)");
}

#[test]
fn test_ttl_above_max_clamped_to_86400() {
    let cache = make_cache();
    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        999_999,
        None,
    );
    let ttl = cache.get_ttl("example.com", &RecordType::A);
    assert_eq!(
        ttl,
        Some(86_400),
        "TTL above max should be clamped to 86400"
    );
}

#[test]
fn test_ttl_within_bounds_unchanged() {
    let cache = make_cache();
    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        300,
        None,
    );
    let ttl = cache.get_ttl("example.com", &RecordType::A);
    assert_eq!(
        ttl,
        Some(300),
        "TTL within valid range should be stored as-is"
    );
}

#[test]
fn test_permanent_records_ignore_bounds() {
    let cache = make_cache();
    cache.insert_permanent("example.com", RecordType::A, make_ip_data("1.2.3.4"), None);
    let ttl = cache.get_ttl("example.com", &RecordType::A);
    let permanent_ttl = 365u32 * 24 * 60 * 60;
    assert_eq!(
        ttl,
        Some(permanent_ttl),
        "Permanent records should retain their large TTL"
    );
}

#[test]
fn test_negative_response_ttl_clamped() {
    let cache = make_cache();
    cache.insert(
        "nxdomain.example.com",
        RecordType::A,
        CachedData::NegativeResponse,
        0,
        None,
    );
    let result = cache.get(&Arc::from("nxdomain.example.com"), &RecordType::A);
    assert!(
        result.is_some(),
        "Negative response with clamped TTL should be retrievable"
    );
    if let Some((_, _, Some(remaining))) = result {
        assert!(
            remaining >= 1,
            "Remaining TTL should be at least 1 after clamping"
        );
    }
}
