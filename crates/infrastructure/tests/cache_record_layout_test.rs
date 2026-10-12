//! Guards the per-entry memory cost: the cache holds up to `cache_max_entries`
//! of these, so a field added to `CachedRecord` multiplies across the whole
//! cache. Grow it only on purpose, and update the numbers here when you do.

use ferrous_dns_infrastructure::dns::cache::CachedRecord;

#[test]
fn test_cached_record_layout_is_unchanged() {
    assert_eq!(std::mem::size_of::<CachedRecord>(), 128);
    assert_eq!(std::mem::align_of::<CachedRecord>(), 64);
}
