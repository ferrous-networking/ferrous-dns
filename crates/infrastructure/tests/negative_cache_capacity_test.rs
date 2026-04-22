//! Tests for Phase 3 of the cache optimization plan: align the negative cache
//! capacity with the positive cache.
//!
//! Historically `NegativeDnsCache::new` clamped the caller-provided capacity at
//! a hard-coded `65_536`. That meant a Pi-hole-style deployment with
//! `cache_max_entries = 200_000` still evicted NXDOMAINs at 65K while the
//! positive cache had plenty of headroom, causing repeated upstream calls for
//! domains that were already known-bad. These tests lock the new behaviour:
//! the configured `max_entries` is respected verbatim, with eviction kicking in
//! only when that configured limit is actually reached.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::negative_cache::NegativeDnsCache;

#[test]
fn should_preserve_configured_max_entries_above_legacy_cap() {
    // The legacy cap was 65_536; we pass 200_000 (production default) and
    // expect it to survive construction unchanged.
    let cache = NegativeDnsCache::new(200_000);

    assert_eq!(
        cache.max_entries(),
        200_000,
        "configured max_entries must survive construction unchanged; legacy \
         65_536 cap must no longer clamp it"
    );
}

#[test]
fn should_evict_when_configured_limit_reached() {
    // Small bounds keep this debug-build test fast: each over-limit insert
    // triggers a DashMap scan looking for expired entries (none here), so
    // cost is O(limit) per over-limit insert.
    let cache = NegativeDnsCache::new(8);

    for i in 0..12 {
        let domain = format!("bad{i}.example.com");
        cache.insert(&domain, RecordType::A, 600);
    }

    assert!(
        cache.len() <= 8,
        "negative cache must enforce the configured max_entries after inserts \
         exceed the limit (got {})",
        cache.len()
    );
}
