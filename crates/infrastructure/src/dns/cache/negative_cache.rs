use super::coarse_clock::coarse_now_secs;
use super::key::CacheKey;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;

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
pub(crate) const MAX_NEGATIVE_TTL: u32 = 3_600;

/// Clamps a negative cache TTL to the `[MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL]`
/// window. Shared with the resolver's cache layer so negative responses from
/// both the SOA path and direct NXDOMAIN insertions use the same bounds.
#[inline]
pub(crate) fn clamp_negative_ttl(ttl: u32) -> u32 {
    ttl.clamp(MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL)
}

struct NegativeEntry {
    expires_at_secs: u64,
}

pub struct NegativeDnsCache {
    cache: DashMap<CacheKey, NegativeEntry, FxBuildHasher>,
    max_entries: usize,
}

impl NegativeDnsCache {
    /// Builds a negative cache with the given capacity ceiling.
    ///
    /// The positive and negative caches share the `cache_max_entries` config so
    /// a Pi-hole-style deployment with a 200K-entry positive cache no longer
    /// evicts NXDOMAINs at 65K while the positive cache still has headroom.
    ///
    /// # Memory sizing
    ///
    /// Each entry costs ~80 bytes (`CacheKey` + `NegativeEntry` + DashMap
    /// overhead). 200K entries ≈ 16 MB. The cap is shared with the positive
    /// cache via `cache_max_entries`.
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: DashMap::with_capacity_and_hasher(max_entries, FxBuildHasher),
            max_entries,
        }
    }

    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "NegativeDnsCache::get expects caller to pass ASCII-lowercased domain; got `{}`",
            domain
        );
        let key = CacheKey::new(domain, *record_type);
        let now = coarse_now_secs();

        match self.cache.get(&key) {
            Some(entry) => {
                let expires = entry.value().expires_at_secs;
                if now < expires {
                    return Some(expires.saturating_sub(now) as u32);
                }
                drop(entry);
                self.cache.remove_if(&key, |_, v| v.expires_at_secs <= now);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, domain: &str, record_type: RecordType, ttl: u32) {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "NegativeDnsCache::insert expects caller to pass ASCII-lowercased domain; got `{}`",
            domain
        );
        let ttl = clamp_negative_ttl(ttl);
        if self.cache.len() >= self.max_entries {
            let now = coarse_now_secs();
            let expired: SmallVec<[CacheKey; EVICTION_BATCH_SIZE]> = self
                .cache
                .iter()
                .take(EVICTION_BATCH_SIZE)
                .filter(|e| now >= e.value().expires_at_secs)
                .map(|e| e.key().clone())
                .collect();
            for k in &expired {
                self.cache.remove(k);
            }
            if self.cache.len() >= self.max_entries {
                let fallback_key = self.cache.iter().next().map(|e| e.key().clone());
                if let Some(key) = fallback_key {
                    self.cache.remove(&key);
                }
            }
        }
        let expires_at_secs = coarse_now_secs() + ttl as u64;
        let key = CacheKey::new(domain, record_type);
        self.cache.insert(key, NegativeEntry { expires_at_secs });
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType) {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "NegativeDnsCache::remove expects caller to pass ASCII-lowercased domain; got `{}`",
            domain
        );
        let key = CacheKey::new(domain, *record_type);
        self.cache.remove(&key);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Removes every entry expired at `now_secs` and returns how many went.
    ///
    /// The insert path only samples a bounded prefix of the map, so expired
    /// entries elsewhere would otherwise hold capacity until read again.
    pub fn purge_expired(&self, now_secs: u64) -> usize {
        let mut removed = 0;
        self.cache.retain(|_, entry| {
            let live = now_secs < entry.expires_at_secs;
            removed += usize::from(!live);
            live
        });
        removed
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_stays_bounded_and_compaction_reclaims_the_rest() {
        let capacity = EVICTION_BATCH_SIZE * 2;
        let cache = NegativeDnsCache::new(capacity);
        for i in 0..capacity {
            cache.cache.insert(
                CacheKey::new(&format!("zone{i}.example"), RecordType::A),
                NegativeEntry { expires_at_secs: 0 },
            );
        }
        // Keep the sampled prefix live and leave the rest expired. Updating
        // values preserves iteration order; release every guard before insert.
        for mut entry in cache.cache.iter_mut().take(EVICTION_BATCH_SIZE) {
            entry.value_mut().expires_at_secs = u64::MAX;
        }

        cache.insert("new.example", RecordType::A, 600);

        // A bounded scan finds no expired entries and evicts one fallback key.
        // Filtering before taking the budget would remove the expired suffix.
        assert_eq!(cache.len(), capacity);
        assert!(cache.get("new.example", &RecordType::A).is_some());

        // The expired suffix the insert did not inspect is reclaimed by the sweep.
        assert_eq!(cache.purge_expired(1), capacity - EVICTION_BATCH_SIZE);
        assert_eq!(cache.len(), EVICTION_BATCH_SIZE);
        assert!(cache.get("new.example", &RecordType::A).is_some());
    }
}
