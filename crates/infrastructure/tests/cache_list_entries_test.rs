use ferrous_dns_application::ports::{CacheEntryOrder, CacheEntryQuery, CacheEntrySort};
use ferrous_dns_domain::{DnssecStatus, RecordType};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, CachedDnssecStatus, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;

fn create_listing_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
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

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

/// CNAME data never reaches the thread-local L1, so `cache.get()` always goes
/// through L2 and increments `hit_count`.
fn make_cname_data(name: &str) -> CachedData {
    CachedData::CanonicalName(Arc::from(name))
}

fn query_all(sort: CacheEntrySort, order: CacheEntryOrder) -> CacheEntryQuery {
    CacheEntryQuery {
        limit: 100,
        sort,
        order,
        ..Default::default()
    }
}

fn domains(entries: &[ferrous_dns_application::ports::CacheEntrySnapshot]) -> Vec<&str> {
    entries.iter().map(|entry| entry.domain.as_str()).collect()
}

#[test]
fn test_list_entries_filters_by_domain_substring_case_insensitive() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert(
        "shop.example.com",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );
    cache.insert(
        "api.example.org",
        RecordType::A,
        make_ip_data("2.2.2.2"),
        300,
        None,
    );
    cache.insert(
        "other.test",
        RecordType::A,
        make_ip_data("3.3.3.3"),
        300,
        None,
    );

    let page = cache.list_entries(&CacheEntryQuery {
        domain: Some("EXAMPLE".to_string()),
        limit: 100,
        sort: CacheEntrySort::Domain,
        order: CacheEntryOrder::Asc,
        ..Default::default()
    });

    assert_eq!(page.total, 2);
    assert_eq!(page.records_total, 3);
    assert_eq!(
        domains(&page.entries),
        vec!["api.example.org", "shop.example.com"]
    );
}

#[test]
fn test_list_entries_filters_by_record_type() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert(
        "dual.test",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );
    cache.insert(
        "dual.test",
        RecordType::AAAA,
        make_ip_data("::1"),
        300,
        None,
    );
    cache.insert(
        "dual.test",
        RecordType::CNAME,
        make_cname_data("target.test"),
        300,
        None,
    );

    let page = cache.list_entries(&CacheEntryQuery {
        record_type: Some(RecordType::AAAA),
        limit: 100,
        ..Default::default()
    });

    assert_eq!(page.total, 1);
    assert_eq!(page.records_total, 3);
    assert_eq!(page.entries[0].record_type, RecordType::AAAA);
}

#[test]
fn test_list_entries_sorts_by_hits_both_directions() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    for (domain, hits) in [("cold.hits", 0), ("warm.hits", 2), ("hot.hits", 5)] {
        cache.insert(
            domain,
            RecordType::CNAME,
            make_cname_data("alias.test"),
            300,
            None,
        );
        for _ in 0..hits {
            assert!(cache.get(domain, &RecordType::CNAME).is_some());
        }
    }

    let desc = cache.list_entries(&query_all(CacheEntrySort::Hits, CacheEntryOrder::Desc));
    assert_eq!(
        domains(&desc.entries),
        vec!["hot.hits", "warm.hits", "cold.hits"]
    );
    assert_eq!(desc.entries[0].hits, 5);

    let asc = cache.list_entries(&query_all(CacheEntrySort::Hits, CacheEntryOrder::Asc));
    assert_eq!(
        domains(&asc.entries),
        vec!["cold.hits", "warm.hits", "hot.hits"]
    );
}

#[test]
fn test_list_entries_sorts_by_domain_both_directions() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    for domain in ["c.sortdomain", "a.sortdomain", "b.sortdomain"] {
        cache.insert(domain, RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    }

    let asc = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));
    assert_eq!(
        domains(&asc.entries),
        vec!["a.sortdomain", "b.sortdomain", "c.sortdomain"]
    );

    let desc = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Desc));
    assert_eq!(
        domains(&desc.entries),
        vec!["c.sortdomain", "b.sortdomain", "a.sortdomain"]
    );
}

#[test]
fn test_list_entries_sorts_by_type_both_directions() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    // A = 1, CNAME = 5, AAAA = 28 (RFC record type codes).
    cache.insert(
        "types.test",
        RecordType::AAAA,
        make_ip_data("::1"),
        300,
        None,
    );
    cache.insert(
        "types.test",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );
    cache.insert(
        "types.test",
        RecordType::CNAME,
        make_cname_data("alias.test"),
        300,
        None,
    );

    let asc = cache.list_entries(&query_all(CacheEntrySort::Type, CacheEntryOrder::Asc));
    let asc_types: Vec<RecordType> = asc.entries.iter().map(|e| e.record_type).collect();
    assert_eq!(
        asc_types,
        vec![RecordType::A, RecordType::CNAME, RecordType::AAAA]
    );

    let desc = cache.list_entries(&query_all(CacheEntrySort::Type, CacheEntryOrder::Desc));
    let desc_types: Vec<RecordType> = desc.entries.iter().map(|e| e.record_type).collect();
    assert_eq!(
        desc_types,
        vec![RecordType::AAAA, RecordType::CNAME, RecordType::A]
    );
}

#[test]
fn test_list_entries_sorts_by_expires_at_both_directions() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    for (domain, ttl) in [("long.exp", 900), ("short.exp", 60), ("mid.exp", 300)] {
        cache.insert(domain, RecordType::A, make_ip_data("1.1.1.1"), ttl, None);
    }

    let asc = cache.list_entries(&query_all(CacheEntrySort::ExpiresAt, CacheEntryOrder::Asc));
    assert_eq!(
        domains(&asc.entries),
        vec!["short.exp", "mid.exp", "long.exp"]
    );

    let desc = cache.list_entries(&query_all(CacheEntrySort::ExpiresAt, CacheEntryOrder::Desc));
    assert_eq!(
        domains(&desc.entries),
        vec!["long.exp", "mid.exp", "short.exp"]
    );
}

#[test]
fn test_list_entries_sorts_by_cached_at_both_directions() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert(
        "first.cached",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );

    // The coarse clock only advances on `tick()`, so both inserts would
    // otherwise share the same `inserted_at_secs`.
    std::thread::sleep(std::time::Duration::from_secs(1));
    coarse_clock::tick();

    cache.insert(
        "second.cached",
        RecordType::A,
        make_ip_data("2.2.2.2"),
        300,
        None,
    );

    let desc = cache.list_entries(&query_all(CacheEntrySort::CachedAt, CacheEntryOrder::Desc));
    assert_eq!(
        domains(&desc.entries),
        vec!["second.cached", "first.cached"]
    );
    assert!(desc.entries[0].cached_at_secs > desc.entries[1].cached_at_secs);

    let asc = cache.list_entries(&query_all(CacheEntrySort::CachedAt, CacheEntryOrder::Asc));
    assert_eq!(domains(&asc.entries), vec!["first.cached", "second.cached"]);
}

#[test]
fn test_list_entries_tie_break_is_deterministic_in_both_orders() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    // Same TTL and same insertion tick: every sort key below ties, so only the
    // `(domain, record type)` tie-break decides the order.
    for domain in ["b.tie", "a.tie", "c.tie"] {
        cache.insert(domain, RecordType::AAAA, make_ip_data("::1"), 300, None);
        cache.insert(domain, RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    }

    let expected = vec![
        ("a.tie", RecordType::A),
        ("a.tie", RecordType::AAAA),
        ("b.tie", RecordType::A),
        ("b.tie", RecordType::AAAA),
        ("c.tie", RecordType::A),
        ("c.tie", RecordType::AAAA),
    ];

    for order in [CacheEntryOrder::Asc, CacheEntryOrder::Desc] {
        let page = cache.list_entries(&query_all(CacheEntrySort::Hits, order));
        let actual: Vec<(&str, RecordType)> = page
            .entries
            .iter()
            .map(|entry| (entry.domain.as_str(), entry.record_type))
            .collect();
        assert_eq!(actual, expected, "tie-break must not depend on the order");
    }
}

#[test]
fn test_list_entries_permanent_entry_has_no_remaining_ttl() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert_permanent(
        "printer.lan",
        RecordType::A,
        make_ip_data("192.168.1.50"),
        None,
    );
    cache.insert(
        "regular.test",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );

    let page = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));

    let permanent = page
        .entries
        .iter()
        .find(|entry| entry.domain == "printer.lan")
        .expect("permanent entry must be listed");
    assert!(permanent.is_permanent);
    assert_eq!(permanent.remaining_ttl, None);
    assert!(!permanent.is_stale);

    let regular = page
        .entries
        .iter()
        .find(|entry| entry.domain == "regular.test")
        .expect("regular entry must be listed");
    assert!(!regular.is_permanent);
    // The coarse clock is process-global, so a parallel test may tick it
    // forward a few seconds between the insert and this listing.
    let remaining = regular.remaining_ttl.expect("regular entry has a TTL");
    assert!(
        (250..=300).contains(&remaining),
        "unexpected remaining TTL: {remaining}"
    );
}

#[test]
fn test_list_entries_maps_dnssec_status() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert(
        "secure.dnssec",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        Some(CachedDnssecStatus::Secure),
    );
    cache.insert(
        "unknown.dnssec",
        RecordType::A,
        make_ip_data("2.2.2.2"),
        300,
        Some(CachedDnssecStatus::Unknown),
    );

    let page = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));

    assert_eq!(page.entries[0].domain, "secure.dnssec");
    assert_eq!(page.entries[0].dnssec_status, Some(DnssecStatus::Secure));
    assert_eq!(page.entries[1].domain, "unknown.dnssec");
    assert_eq!(page.entries[1].dnssec_status, None);
}

#[test]
fn test_list_entries_exposes_answers_and_canonical_name() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    cache.insert(
        "addresses.test",
        RecordType::A,
        make_ip_data("203.0.113.7"),
        300,
        None,
    );
    cache.insert(
        "alias.test",
        RecordType::CNAME,
        make_cname_data("canonical.test"),
        300,
        None,
    );

    let page = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));

    let addresses = &page.entries[0];
    assert_eq!(addresses.domain, "addresses.test");
    assert_eq!(addresses.answers.len(), 1);
    assert_eq!(addresses.answers[0].to_string(), "203.0.113.7");
    assert_eq!(addresses.canonical_name, None);

    let alias = &page.entries[1];
    assert_eq!(alias.domain, "alias.test");
    assert!(alias.answers.is_empty());
    assert_eq!(alias.canonical_name, Some("canonical.test".to_string()));
}

#[test]
fn test_list_entries_total_counts_filter_while_records_total_counts_cache() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    for domain in ["a.counted", "b.counted", "c.other"] {
        cache.insert(domain, RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    }

    let page = cache.list_entries(&CacheEntryQuery {
        domain: Some("counted".to_string()),
        limit: 1,
        ..Default::default()
    });

    assert_eq!(page.entries.len(), 1, "limit caps the returned page");
    assert_eq!(page.total, 2, "total counts every filtered entry");
    assert_eq!(page.records_total, 3, "records_total ignores the filter");
}

#[test]
fn test_list_entries_paginates_with_offset() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    for domain in ["a.page", "b.page", "c.page", "d.page", "e.page"] {
        cache.insert(domain, RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    }

    let first = cache.list_entries(&CacheEntryQuery {
        sort: CacheEntrySort::Domain,
        order: CacheEntryOrder::Asc,
        limit: 2,
        offset: 0,
        ..Default::default()
    });
    assert_eq!(domains(&first.entries), vec!["a.page", "b.page"]);
    assert_eq!(first.total, 5);

    let second = cache.list_entries(&CacheEntryQuery {
        sort: CacheEntrySort::Domain,
        order: CacheEntryOrder::Asc,
        limit: 2,
        offset: 2,
        ..Default::default()
    });
    assert_eq!(domains(&second.entries), vec!["c.page", "d.page"]);
    assert_eq!(second.total, 5);

    let last = cache.list_entries(&CacheEntryQuery {
        sort: CacheEntrySort::Domain,
        order: CacheEntryOrder::Asc,
        limit: 2,
        offset: 4,
        ..Default::default()
    });
    assert_eq!(domains(&last.entries), vec!["e.page"]);

    let past_end = cache.list_entries(&CacheEntryQuery {
        sort: CacheEntrySort::Domain,
        order: CacheEntryOrder::Asc,
        limit: 2,
        offset: 10,
        ..Default::default()
    });
    assert!(past_end.entries.is_empty());
    assert_eq!(past_end.total, 5, "total stays independent of the offset");
}

#[test]
fn test_list_entries_omits_negative_responses() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    // Negative answers are routed to the separate negative cache, never to the
    // positive map this listing walks.
    cache.insert(
        "nxdomain.test",
        RecordType::A,
        CachedData::NegativeResponse,
        300,
        None,
    );
    cache.insert(
        "positive.test",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        300,
        None,
    );

    let page = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));

    assert_eq!(domains(&page.entries), vec!["positive.test"]);
    assert_eq!(page.total, 1);
    assert_eq!(page.records_total, 1);
}

#[test]
fn test_list_entries_keeps_stale_and_drops_fully_expired() {
    let cache = create_listing_cache();
    coarse_clock::tick();

    // Stale grace period is 2×TTL: after 4s the TTL=3 entry is expired but
    // still served, while the TTL=1 entry is past its grace window.
    cache.insert(
        "stale.expiry",
        RecordType::CNAME,
        make_cname_data("alias.test"),
        3,
        None,
    );
    cache.insert(
        "gone.expiry",
        RecordType::CNAME,
        make_cname_data("alias.test"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_secs(4));
    coarse_clock::tick();

    let page = cache.list_entries(&query_all(CacheEntrySort::Domain, CacheEntryOrder::Asc));

    assert_eq!(domains(&page.entries), vec!["stale.expiry"]);
    assert_eq!(page.total, 1);
    assert!(page.entries[0].is_stale, "stale entry must be flagged");
    assert_eq!(page.entries[0].remaining_ttl, Some(0));
    assert_eq!(
        page.records_total, 2,
        "records_total reflects the raw cache, including the expired entry"
    );
}
