use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

/// L1 cache entry with expiration
struct L1Entry {
    addresses: Arc<Vec<IpAddr>>,
    expires_at: Instant,
}

thread_local! {
    static L1_CACHE: RefCell<LruCache<(CompactString, RecordType), L1Entry, FxBuildHasher>> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(512).unwrap(),
            FxBuildHasher
        ));

    static L1_STATS: RefCell<L1CacheStats> = RefCell::new(L1CacheStats::default());
}

/// Statistics for L1 cache performance tracking
#[derive(Default, Clone, Copy)]
pub struct L1CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expirations: u64,
}

impl L1CacheStats {
    /// Calculate hit rate (0.0 to 1.0)
    pub fn hit_rate(&self) -> f64 {
        if self.hits + self.misses == 0 {
            0.0
        } else {
            self.hits as f64 / (self.hits + self.misses) as f64
        }
    }
}

/// Try to get IP addresses from L1 cache
///
/// Returns Some(addresses) if found and not expired, None otherwise
#[inline]
pub fn l1_get(domain: &str, record_type: &RecordType) -> Option<Arc<Vec<IpAddr>>> {
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (CompactString::new(domain), *record_type);

        if let Some(entry) = cache.get(&key) {
            // Check if expired
            if Instant::now() < entry.expires_at {
                // Valid cache HIT
                L1_STATS.with(|stats| stats.borrow_mut().hits += 1);
                return Some(Arc::clone(&entry.addresses));
            } else {
                // Expired - remove it
                cache.pop(&key);
                L1_STATS.with(|stats| stats.borrow_mut().expirations += 1);
            }
        }

        // Cache MISS
        L1_STATS.with(|stats| stats.borrow_mut().misses += 1);
        None
    })
}

/// Insert IP addresses into L1 cache with TTL
#[inline]
pub fn l1_insert(
    domain: &str,
    record_type: &RecordType,
    addresses: Arc<Vec<IpAddr>>,
    ttl_secs: u32,
) {
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (CompactString::new(domain), *record_type);
        let entry = L1Entry {
            addresses,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
        };
        cache.put(key, entry);
    });
}

/// Get L1 cache statistics
pub fn l1_cache_stats() -> L1CacheStats {
    L1_STATS.with(|stats| *stats.borrow())
}
