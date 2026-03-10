use ferrous_dns_infrastructure::dns::tunneling::client_stats::{
    fx_hash_str, subnet_key_from_ip, ClientApexStats, TrackingKey,
};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

// ── TrackingKey ─────────────────────────────────────────────────────────────

#[test]
fn tracking_key_equal_when_same_values() {
    let a = TrackingKey {
        subnet: 100,
        apex_hash: 200,
    };
    let b = TrackingKey {
        subnet: 100,
        apex_hash: 200,
    };
    assert_eq!(a, b);
}

#[test]
fn tracking_key_different_when_values_differ() {
    let a = TrackingKey {
        subnet: 100,
        apex_hash: 200,
    };
    let b = TrackingKey {
        subnet: 200,
        apex_hash: 100,
    };
    assert_ne!(a, b);
}

#[test]
fn tracking_key_no_symmetric_collision() {
    let a = TrackingKey {
        subnet: 1,
        apex_hash: 2,
    };
    let b = TrackingKey {
        subnet: 2,
        apex_hash: 1,
    };

    fn compute_hash(key: &TrackingKey) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    assert_ne!(
        compute_hash(&a),
        compute_hash(&b),
        "swapped subnet/apex_hash should not produce same hash"
    );
}

// ── ClientApexStats ─────────────────────────────────────────────────────────

#[test]
fn new_stats_have_zero_counters() {
    let stats = ClientApexStats::new(1000);
    assert_eq!(stats.query_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.unique_subdomain_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.txt_query_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.nxdomain_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.last_seen_ns.load(Ordering::Relaxed), 1000);
    assert_eq!(stats.window_start_ns.load(Ordering::Relaxed), 1000);
}

#[test]
fn reset_window_clears_all_counters() {
    let stats = ClientApexStats::new(1000);
    stats.query_count.store(50, Ordering::Relaxed);
    stats.unique_subdomain_count.store(30, Ordering::Relaxed);
    stats.txt_query_count.store(10, Ordering::Relaxed);
    stats.nxdomain_count.store(5, Ordering::Relaxed);
    stats.total_count.store(80, Ordering::Relaxed);

    stats.reset_window(2000);

    assert_eq!(stats.query_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.unique_subdomain_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.txt_query_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.nxdomain_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.window_start_ns.load(Ordering::Relaxed), 2000);
}

#[test]
fn reset_window_clears_bloom_filter() {
    let stats = ClientApexStats::new(1000);
    stats.bloom_add(0xDEAD_BEEF);
    stats.bloom_add(0xCAFE_BABE);

    stats.reset_window(2000);

    for slot in &stats.mini_bloom {
        assert_eq!(slot.load(Ordering::Relaxed), 0);
    }
}

// ── Bloom filter ────────────────────────────────────────────────────────────

#[test]
fn bloom_add_new_element_returns_true() {
    let stats = ClientApexStats::new(0);
    assert!(stats.bloom_add(42));
}

#[test]
fn bloom_add_duplicate_returns_false() {
    let stats = ClientApexStats::new(0);
    assert!(stats.bloom_add(42));
    assert!(
        !stats.bloom_add(42),
        "second add of same hash should return false"
    );
}

#[test]
fn bloom_add_different_elements_return_true() {
    let stats = ClientApexStats::new(0);
    assert!(stats.bloom_add(1));
    assert!(stats.bloom_add(2));
    assert!(stats.bloom_add(1000));
}

#[test]
fn bloom_has_low_false_positive_rate_for_small_sets() {
    let stats = ClientApexStats::new(0);
    let mut new_count = 0;
    for i in 0..50u64 {
        if stats.bloom_add(i * 7919) {
            new_count += 1;
        }
    }
    // With 256 bits and 2 hash functions, 50 inserts should have very few FPs
    assert!(
        new_count >= 45,
        "expected at least 45 new elements, got {new_count}"
    );
}

// ── subnet_key_from_ip ──────────────────────────────────────────────────────

#[test]
fn ipv4_same_subnet_produces_same_key() {
    let a: IpAddr = "192.168.1.100".parse().unwrap();
    let b: IpAddr = "192.168.1.200".parse().unwrap();
    assert_eq!(subnet_key_from_ip(a, 24, 48), subnet_key_from_ip(b, 24, 48));
}

#[test]
fn ipv4_different_subnet_produces_different_key() {
    let a: IpAddr = "192.168.1.100".parse().unwrap();
    let b: IpAddr = "192.168.2.100".parse().unwrap();
    assert_ne!(subnet_key_from_ip(a, 24, 48), subnet_key_from_ip(b, 24, 48));
}

#[test]
fn ipv6_same_subnet_produces_same_key() {
    let a: IpAddr = "2001:db8::1".parse().unwrap();
    let b: IpAddr = "2001:db8::ffff".parse().unwrap();
    assert_eq!(subnet_key_from_ip(a, 24, 48), subnet_key_from_ip(b, 24, 48));
}

#[test]
fn ipv6_different_subnet_with_48_prefix_produces_different_key() {
    let a: IpAddr = "2001:db8:1::1".parse().unwrap();
    let b: IpAddr = "2001:db8:2::1".parse().unwrap();
    assert_ne!(subnet_key_from_ip(a, 24, 48), subnet_key_from_ip(b, 24, 48));
}

// ── fx_hash_str ─────────────────────────────────────────────────────────────

#[test]
fn fx_hash_same_string_produces_same_hash() {
    assert_eq!(fx_hash_str("example.com"), fx_hash_str("example.com"));
}

#[test]
fn fx_hash_different_strings_produce_different_hashes() {
    assert_ne!(fx_hash_str("example.com"), fx_hash_str("example.org"));
}
