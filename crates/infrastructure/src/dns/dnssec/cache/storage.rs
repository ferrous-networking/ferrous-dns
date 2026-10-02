use super::super::types::{DnskeyRecord, DsLookup};
use super::entries::CacheEntry;
use super::stats::{CacheStats, CacheStatsSnapshot};
use crate::counted_map::CountedDashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Per-map ceiling on cached zones. Without it, a stream of queries naming
/// distinct (attacker-chosen) signer zones would grow these maps without bound
/// — a memory-exhaustion vector, since every cold chain walk inserts a DS and a
/// DNSKEY entry. The real namespace a recursor touches is far smaller than this.
const MAX_ENTRIES: usize = 50_000;

/// Maximum entries inspected for expiration per full-cache insert before
/// falling back to evicting an arbitrary entry.
const EVICTION_BATCH_SIZE: usize = 32;

pub struct DnssecCache {
    dnskeys: CountedDashMap<Arc<str>, CacheEntry<Arc<[DnskeyRecord]>>>,

    ds_lookups: CountedDashMap<Arc<str>, CacheEntry<DsLookup>>,

    stats: CacheStats,
}

impl DnssecCache {
    pub fn new() -> Self {
        Self {
            dnskeys: CountedDashMap::new(),
            ds_lookups: CountedDashMap::new(),
            stats: CacheStats::default(),
        }
    }

    pub fn cache_dnskey(&self, domain: &str, keys: Arc<[DnskeyRecord]>, ttl_seconds: u32) {
        insert(&self.dnskeys, domain, keys, ttl_seconds);
        trace!(domain = %domain, ttl = ttl_seconds, "Cached DNSKEY records");
    }

    pub fn get_dnskey(&self, domain: &str) -> Option<Arc<[DnskeyRecord]>> {
        let hit = lookup(&self.dnskeys, domain);
        if hit.is_some() {
            self.stats.record_dnskey_hit();
        } else {
            self.stats.record_dnskey_miss();
        }
        hit
    }

    /// Caches an authenticated DS answer: the parent-signed RRset or the
    /// parent's signed denial. Never call this with unauthenticated data.
    pub fn cache_ds(&self, domain: &str, ds: DsLookup, ttl_seconds: u32) {
        trace!(domain = %domain, ttl = ttl_seconds, ds = ?ds, "Cached DS lookup");
        insert(&self.ds_lookups, domain, ds, ttl_seconds);
    }

    pub fn get_ds(&self, domain: &str) -> Option<DsLookup> {
        let hit = lookup(&self.ds_lookups, domain);
        if hit.is_some() {
            self.stats.record_ds_hit();
        } else {
            self.stats.record_ds_miss();
        }
        hit
    }

    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            dnskey_entries: self.dnskeys.len(),
            ds_entries: self.ds_lookups.len(),
            total_dnskey_hits: self.stats.total_dnskey_hits(),
            total_dnskey_misses: self.stats.total_dnskey_misses(),
            total_ds_hits: self.stats.total_ds_hits(),
            total_ds_misses: self.stats.total_ds_misses(),
            total_ds_denials_unproven: self.stats.total_ds_denials_unproven(),
        }
    }

    /// See [`CacheStats::record_ds_denial_unproven`].
    pub fn record_ds_denial_unproven(&self) {
        self.stats.record_ds_denial_unproven();
    }
}

fn insert<V>(
    map: &CountedDashMap<Arc<str>, CacheEntry<V>>,
    domain: &str,
    value: V,
    ttl_seconds: u32,
) {
    map.evict_if_full::<EVICTION_BATCH_SIZE>(MAX_ENTRIES, CacheEntry::is_expired);
    map.insert(Arc::from(domain), CacheEntry::new(value, ttl_seconds));
}

fn lookup<V: Clone>(map: &CountedDashMap<Arc<str>, CacheEntry<V>>, domain: &str) -> Option<V> {
    let entry = map.get(domain)?;
    if !entry.is_expired() {
        return Some(entry.get().clone());
    }
    drop(entry);
    // Conditional: a concurrent validator may have re-cached a fresh set since the read.
    map.remove_if(domain, |_, entry| entry.is_expired());
    debug!(domain = %domain, "DNSSEC cache entry expired");
    None
}

impl Default for DnssecCache {
    fn default() -> Self {
        Self::new()
    }
}
