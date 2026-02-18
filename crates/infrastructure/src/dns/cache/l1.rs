use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

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

#[derive(Default, Clone, Copy)]
pub struct L1CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expirations: u64,
}

impl L1CacheStats {
    
    pub fn hit_rate(&self) -> f64 {
        if self.hits + self.misses == 0 {
            0.0
        } else {
            self.hits as f64 / (self.hits + self.misses) as f64
        }
    }
}

#[inline]
pub fn l1_get(domain: &str, record_type: &RecordType) -> Option<Arc<Vec<IpAddr>>> {
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (CompactString::new(domain), *record_type);

        if let Some(entry) = cache.get(&key) {
            
            if Instant::now() < entry.expires_at {
                
                L1_STATS.with(|stats| stats.borrow_mut().hits += 1);
                return Some(Arc::clone(&entry.addresses));
            } else {
                
                cache.pop(&key);
                L1_STATS.with(|stats| stats.borrow_mut().expirations += 1);
            }
        }

        L1_STATS.with(|stats| stats.borrow_mut().misses += 1);
        None
    })
}

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

pub fn l1_cache_stats() -> L1CacheStats {
    L1_STATS.with(|stats| *stats.borrow())
}
