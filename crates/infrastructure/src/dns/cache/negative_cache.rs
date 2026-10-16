use super::coarse_clock::coarse_now_secs;
use super::key::CacheKey;
use crate::counted_map::CountedDashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;

/// Maximum entries inspected for expiration per full-cache insert.
const EVICTION_BATCH_SIZE: usize = 64;

/// Minimum TTL applied to negative cache entries. Upstream resolvers sometimes
/// return TTL=0 for NXDOMAIN/NoData (or the local config has `cache_min_ttl=0`
/// to keep positive records short), which would cause negative entries to
/// expire immediately and every repeated miss to escape to upstream. A 300s
/// floor keeps repeated lookups for non-existent domains served from cache.
pub(crate) const MIN_NEGATIVE_TTL: u32 = 300;

/// Maximum TTL applied to negative cache entries. Caps how long a stale
/// NXDOMAIN can linger if the upstream advertises an unreasonable SOA TTL.
const MAX_NEGATIVE_TTL: u32 = 3_600;

/// How long a negative answer is cached: the SOA's negative TTL, held to the
/// `[MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL]` window.
pub(crate) fn negative_ttl(soa_ttl: Option<u32>) -> u32 {
    soa_ttl
        .unwrap_or(MIN_NEGATIVE_TTL)
        .clamp(MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL)
}

/// Marks an entry from the local DNS server in the top bit of its expiry,
/// which epoch seconds never reach; the entry stays one `u64`.
const LOCAL_DNS_BIT: u64 = 1 << 63;

struct NegativeEntry {
    expiry_and_source: u64,
}

impl NegativeEntry {
    fn new(expires_at_secs: u64, local_dns: bool) -> Self {
        let source = if local_dns { LOCAL_DNS_BIT } else { 0 };
        Self {
            expiry_and_source: (expires_at_secs & !LOCAL_DNS_BIT) | source,
        }
    }

    #[inline]
    fn expires_at_secs(&self) -> u64 {
        self.expiry_and_source & !LOCAL_DNS_BIT
    }

    #[inline]
    fn is_local_dns(&self) -> bool {
        self.expiry_and_source & LOCAL_DNS_BIT != 0
    }
}

pub struct NegativeDnsCache {
    cache: CountedDashMap<CacheKey, NegativeEntry, FxBuildHasher>,
    max_entries: usize,
}

impl NegativeDnsCache {
    /// Builds a negative cache with the given capacity ceiling, the same
    /// `cache_max_entries` the positive cache is sized by.
    ///
    /// # Memory sizing
    ///
    /// Each entry costs ~80 bytes (`CacheKey` + `NegativeEntry` + DashMap
    /// overhead). 200K entries ≈ 16 MB.
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: CountedDashMap::with_capacity_and_hasher(max_entries, FxBuildHasher),
            max_entries,
        }
    }

    /// Remaining TTL and whether the local DNS server gave the answer, in
    /// cache view `view` (0 for the one every client shares).
    pub fn get(&self, domain: &str, record_type: &RecordType, view: u32) -> Option<(u32, bool)> {
        let key = CacheKey::from_lowercase(domain, *record_type).in_view(view);
        let now = coarse_now_secs();

        match self.cache.get(&key) {
            Some(entry) => {
                let expires = entry.value().expires_at_secs();
                if now < expires {
                    return Some((
                        expires.saturating_sub(now) as u32,
                        entry.value().is_local_dns(),
                    ));
                }
                drop(entry);
                self.cache
                    .remove_if(&key, |_, v| v.expires_at_secs() <= now);
                None
            }
            None => None,
        }
    }

    /// Stores the entry and returns the second it expires.
    pub fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        ttl: u32,
        local_dns: bool,
        view: u32,
    ) -> u64 {
        let ttl = negative_ttl(Some(ttl));
        let now = coarse_now_secs();
        self.cache
            .evict_if_full::<EVICTION_BATCH_SIZE>(self.max_entries, |entry| {
                now >= entry.expires_at_secs()
            });
        let key = CacheKey::from_lowercase(domain, record_type).in_view(view);
        let expires_at_secs = now + ttl as u64;
        self.cache
            .insert(key, NegativeEntry::new(expires_at_secs, local_dns));
        expires_at_secs
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType, view: u32) {
        let key = CacheKey::from_lowercase(domain, *record_type).in_view(view);
        self.cache.remove(&key);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Whether `key` is held, expired or not.
    pub fn contains(&self, key: &CacheKey) -> bool {
        self.cache.get(key).is_some()
    }

    /// Removes `key` if it expired by `now_secs`, for the timer its insert
    /// armed. An entry stored over it since keeps its own, later expiry.
    pub fn remove_expired(&self, key: &CacheKey, now_secs: u64) -> bool {
        self.cache
            .remove_if(key, |_, entry| entry.expires_at_secs() <= now_secs)
            .is_some()
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_stays_bounded_and_expiry_reclaims_the_rest() {
        let capacity = EVICTION_BATCH_SIZE * 2;
        let cache = NegativeDnsCache::new(capacity);
        let keys: Vec<CacheKey> = (0..capacity)
            .map(|i| CacheKey::new(&format!("zone{i}.example"), RecordType::A))
            .collect();
        for key in &keys {
            cache
                .cache
                .insert(key.clone(), NegativeEntry::new(0, false));
        }
        // Keep the sampled prefix live and leave the rest expired. Updating
        // values preserves iteration order; release every guard before insert.
        for mut entry in cache.cache.iter_mut().take(EVICTION_BATCH_SIZE) {
            *entry.value_mut() = NegativeEntry::new(u64::MAX, false);
        }

        cache.insert("new.example", RecordType::A, 600, false, 0);

        // A bounded scan finds no expired entries and evicts one fallback key.
        // Filtering before taking the budget would remove the expired suffix.
        assert_eq!(cache.len(), capacity);
        assert!(cache.get("new.example", &RecordType::A, 0).is_some());

        // The expired suffix the insert did not inspect goes as each entry's
        // own expiry fires; the live prefix stays.
        let expired = keys
            .iter()
            .filter(|key| cache.remove_expired(key, 1))
            .count();
        assert_eq!(expired, capacity - EVICTION_BATCH_SIZE);
        assert_eq!(cache.len(), EVICTION_BATCH_SIZE);
        assert!(cache.get("new.example", &RecordType::A, 0).is_some());
    }

    #[test]
    fn expiry_keeps_an_entry_stored_over_the_expired_one() {
        let cache = NegativeDnsCache::new(16);
        let first = cache.insert("gone.example", RecordType::A, 300, false, 0);
        let key = CacheKey::new("gone.example", RecordType::A);

        assert!(!cache.remove_expired(&key, first - 1), "not expired yet");
        cache
            .cache
            .insert(key.clone(), NegativeEntry::new(first + 300, false));
        assert!(
            !cache.remove_expired(&key, first),
            "the first expiry must not remove the entry stored over it"
        );
        assert!(cache.remove_expired(&key, first + 300));
        assert!(cache.is_empty());
    }
}
