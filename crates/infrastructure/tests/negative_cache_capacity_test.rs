//! The negative cache holds exactly its configured capacity: it fills to the
//! limit and then evicts one entry per insert instead of growing.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::negative_cache::NegativeDnsCache;

#[test]
fn should_evict_when_configured_limit_reached() {
    // More live entries than the expiration scan budget exercises fallback
    // eviction without requiring a full-cache scan.
    const CAPACITY: usize = 256;
    let cache = NegativeDnsCache::new(CAPACITY);

    for i in 0..CAPACITY + 4 {
        let domain = format!("bad{i}.example.com");
        cache.insert(&domain, RecordType::A, 600, false, 0);
        assert!(cache.get(&domain, &RecordType::A, 0).is_some());
        assert_eq!(cache.len(), (i + 1).min(CAPACITY));
    }
}
