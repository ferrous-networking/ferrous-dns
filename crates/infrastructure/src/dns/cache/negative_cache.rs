use super::coarse_clock::coarse_now_secs;
use super::key::CacheKey;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;

const MAX_ENTRIES_CAP: usize = 65_536;
const EVICTION_BATCH_SIZE: usize = 64;

struct NegativeEntry {
    expires_at_secs: u64,
}

/// Separate cache for negative DNS responses (NXDOMAIN / NODATA).
///
/// In blocker workloads 50-70% of queries result in NXDOMAIN. Keeping
/// negative entries in the same DashMap as positive entries causes shard
/// contention, biases eviction scoring, and inflates the bloom filter's
/// false-positive rate. This lightweight cache uses a plain DashMap with
/// TTL expiry and no scoring overhead.
pub struct NegativeDnsCache {
    cache: DashMap<CacheKey, NegativeEntry, FxBuildHasher>,
    max_entries: usize,
}

impl NegativeDnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: DashMap::with_capacity_and_hasher(
                max_entries.min(MAX_ENTRIES_CAP),
                FxBuildHasher,
            ),
            max_entries,
        }
    }

    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain, *record_type);
        let now = coarse_now_secs();
        match self.cache.entry(key) {
            dashmap::Entry::Vacant(_) => None,
            dashmap::Entry::Occupied(e) => {
                let expires = e.get().expires_at_secs;
                if now >= expires {
                    e.remove();
                    None
                } else {
                    Some(expires.saturating_sub(now) as u32)
                }
            }
        }
    }

    pub fn insert(&self, domain: &str, record_type: RecordType, ttl: u32) {
        if self.cache.len() >= self.max_entries {
            let now = coarse_now_secs();
            let expired: Vec<CacheKey> = self
                .cache
                .iter()
                .filter(|e| now >= e.value().expires_at_secs)
                .map(|e| e.key().clone())
                .take(EVICTION_BATCH_SIZE)
                .collect();
            for k in &expired {
                self.cache.remove(k);
            }
            if self.cache.len() >= self.max_entries {
                if let Some(k) = self.cache.iter().map(|e| e.key().clone()).next() {
                    self.cache.remove(&k);
                }
            }
        }
        let expires_at_secs = coarse_now_secs() + ttl as u64;
        let key = CacheKey::new(domain, record_type);
        self.cache.insert(key, NegativeEntry { expires_at_secs });
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain, *record_type);
        self.cache.remove(&key);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}
