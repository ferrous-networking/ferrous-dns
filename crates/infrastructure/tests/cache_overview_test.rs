//! The dashboard's cache overview: the most renewed entries and how many
//! entries are about to expire, from one pass over the cache.

use ferrous_dns_application::ports::CacheTopRefreshed;
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

const EXPIRING_WINDOW_SECS: u64 = 60;

fn create_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::HitRate,
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
    })
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

fn insert(cache: &DnsCache, domain: &str, record_type: RecordType, ttl: u32) {
    cache.insert(domain, record_type, make_ip_data("1.1.1.1"), ttl, None);
}

fn renew(cache: &DnsCache, domain: &str, record_type: RecordType, times: usize) {
    for _ in 0..times {
        assert!(cache.refresh_record(
            domain,
            &record_type,
            Some(300),
            make_ip_data("1.1.1.1"),
            None,
        ));
    }
}

fn ranked(top: &[CacheTopRefreshed]) -> Vec<(&str, RecordType, u64)> {
    top.iter()
        .map(|entry| (entry.domain.as_str(), entry.record_type, entry.refreshes))
        .collect()
}

#[test]
fn test_overview_lists_the_most_renewed_entries_first() {
    let cache = create_cache();
    coarse_clock::tick();

    for (domain, times) in [
        ("one.test", 1),
        ("four.test", 4),
        ("never.test", 0),
        ("two.test", 2),
        ("three-b.test", 3),
        ("three-a.test", 3),
        ("five.test", 5),
    ] {
        insert(&cache, domain, RecordType::A, 300);
        renew(&cache, domain, RecordType::A, times);
    }

    let overview = cache.overview(5, EXPIRING_WINDOW_SECS);

    assert_eq!(
        ranked(&overview.top_refreshed),
        vec![
            ("five.test", RecordType::A, 5),
            ("four.test", RecordType::A, 4),
            ("three-a.test", RecordType::A, 3),
            ("three-b.test", RecordType::A, 3),
            ("two.test", RecordType::A, 2),
        ],
        "most renewed first, ties by domain, the sixth left out"
    );
}

#[test]
fn test_overview_lists_each_record_type_of_a_name_on_its_own() {
    let cache = create_cache();
    coarse_clock::tick();

    insert(&cache, "dual.test", RecordType::A, 300);
    insert(&cache, "dual.test", RecordType::AAAA, 300);
    renew(&cache, "dual.test", RecordType::A, 2);
    renew(&cache, "dual.test", RecordType::AAAA, 2);

    let overview = cache.overview(5, EXPIRING_WINDOW_SECS);

    assert_eq!(
        ranked(&overview.top_refreshed),
        vec![
            ("dual.test", RecordType::A, 2),
            ("dual.test", RecordType::AAAA, 2),
        ]
    );
}

#[test]
fn test_overview_leaves_out_entries_never_renewed() {
    let cache = create_cache();
    coarse_clock::tick();

    insert(&cache, "fresh.test", RecordType::A, 300);

    assert!(cache
        .overview(5, EXPIRING_WINDOW_SECS)
        .top_refreshed
        .is_empty());
}

#[test]
fn test_overview_counts_entries_whose_ttl_ends_within_the_window() {
    let cache = create_cache();
    coarse_clock::tick();

    insert(&cache, "soon.test", RecordType::A, 30);
    insert(&cache, "edge.test", RecordType::A, 60);
    insert(&cache, "later.test", RecordType::A, 300);
    cache.insert_permanent(
        "printer.lan",
        RecordType::A,
        make_ip_data("192.168.1.50"),
        30,
    );

    assert_eq!(
        cache.overview(5, EXPIRING_WINDOW_SECS).expiring_soon,
        2,
        "TTL 30 and 60 end within 60 s; TTL 300 does not, and a local record never expires"
    );
}

#[test]
fn test_overview_does_not_count_an_entry_already_past_its_ttl() {
    let cache = create_cache();
    coarse_clock::tick();

    insert(&cache, "stale.test", RecordType::A, 1);
    std::thread::sleep(Duration::from_millis(1_100));
    coarse_clock::tick();

    assert_eq!(
        cache.overview(5, EXPIRING_WINDOW_SECS).expiring_soon,
        0,
        "an entry served stale has already expired"
    );
}
