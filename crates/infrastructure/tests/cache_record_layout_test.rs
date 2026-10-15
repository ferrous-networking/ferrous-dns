//! Guards the per-entry memory cost: the cache holds up to `cache_max_entries`
//! of these, so a field added to `CachedRecord` multiplies across the whole
//! cache. Grow it only on purpose, and update the numbers here when you do.

use ferrous_dns_infrastructure::dns::cache::{CacheKey, CachedRecord};

#[test]
fn test_cached_record_layout_is_unchanged() {
    assert_eq!(std::mem::size_of::<CachedRecord>(), 128);
    assert_eq!(std::mem::align_of::<CachedRecord>(), 64);
}

/// Every entry also stores its key, and the in-flight map one per pending
/// lookup; the per-group view must fit the key's existing padding.
#[test]
fn test_cache_key_layout_is_unchanged() {
    assert_eq!(std::mem::size_of::<CacheKey>(), 32);
}
