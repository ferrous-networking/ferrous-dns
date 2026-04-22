use super::coarse_clock::coarse_now_secs;
use super::key::CacheKey;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;

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
                .filter(|e| now >= e.value().expires_at_secs)
                .map(|e| e.key().clone())
                .take(EVICTION_BATCH_SIZE)
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
