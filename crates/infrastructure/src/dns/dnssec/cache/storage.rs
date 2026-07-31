use super::super::types::{DnskeyRecord, DsRecord};
use super::entries::{DnskeyEntry, DsEntry};
use super::stats::{CacheStats, CacheStatsSnapshot};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Per-map ceiling on cached zones. Without it, a stream of queries naming
/// distinct (attacker-chosen) signer zones would grow these maps without bound
/// — a memory-exhaustion vector, since every cold chain walk inserts a DS and a
/// DNSKEY entry. The real namespace a recursor touches is far smaller than this.
const MAX_ENTRIES: usize = 50_000;

/// How many expired entries to sweep per over-capacity insert before falling
/// back to evicting an arbitrary entry. Bounds the work done while holding the
/// insert path open, mirroring the main negative cache.
const EVICTION_BATCH_SIZE: usize = 32;

pub struct DnssecCache {
    dnskeys: DashMap<Arc<str>, DnskeyEntry>,

    ds_records: DashMap<Arc<str>, DsEntry>,

    stats: Arc<CacheStats>,
}

impl DnssecCache {
    pub fn new() -> Self {
        Self {
            dnskeys: DashMap::new(),
            ds_records: DashMap::new(),
            stats: Arc::new(CacheStats::default()),
        }
    }

    pub fn cache_dnskey(&self, domain: &str, keys: Vec<DnskeyRecord>, ttl_seconds: u32) {
        let key = Arc::from(domain);
        let entry = DnskeyEntry::new(keys, ttl_seconds);

        evict_if_full(&self.dnskeys, DnskeyEntry::is_expired);
        self.dnskeys.insert(key, entry);

        trace!(
            domain = %domain,
            ttl = ttl_seconds,
            "Cached DNSKEY records"
        );
    }

    pub fn get_dnskey(&self, domain: &str) -> Option<Arc<[DnskeyRecord]>> {
        if let Some(entry) = self.dnskeys.get(domain) {
            if !entry.is_expired() {
                self.stats.record_dnskey_hit(domain);

                trace!(
                    domain = %domain,
                    "DNSKEY cache hit"
                );

                return Some(Arc::clone(entry.keys()));
            } else {
                drop(entry);
                self.dnskeys.remove(domain);

                debug!(
                    domain = %domain,
                    "DNSKEY cache expired"
                );
            }
        }

        self.stats.record_dnskey_miss(domain);
        None
    }

    pub fn cache_ds(&self, domain: &str, records: Vec<DsRecord>, ttl_seconds: u32) {
        let key = Arc::from(domain);
        let entry = DsEntry::new(records, ttl_seconds);

        evict_if_full(&self.ds_records, DsEntry::is_expired);
        self.ds_records.insert(key, entry);

        trace!(
            domain = %domain,
            ttl = ttl_seconds,
            "Cached DS records"
        );
    }

    pub fn get_ds(&self, domain: &str) -> Option<Arc<[DsRecord]>> {
        if let Some(entry) = self.ds_records.get(domain) {
            if !entry.is_expired() {
                self.stats.record_ds_hit(domain);

                trace!(
                    domain = %domain,
                    "DS cache hit"
                );

                return Some(Arc::clone(entry.records()));
            } else {
                drop(entry);
                self.ds_records.remove(domain);

                debug!(
                    domain = %domain,
                    "DS cache expired"
                );
            }
        }

        self.stats.record_ds_miss(domain);
        None
    }

    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            dnskey_entries: self.dnskeys.len(),
            ds_entries: self.ds_records.len(),
            total_dnskey_hits: self.stats.total_dnskey_hits(),
            total_dnskey_misses: self.stats.total_dnskey_misses(),
            total_ds_hits: self.stats.total_ds_hits(),
            total_ds_misses: self.stats.total_ds_misses(),
            total_ds_denial_fail_opens: self.stats.total_ds_denial_fail_opens(),
        }
    }

    /// See [`CacheStats::record_ds_denial_fail_open`].
    pub fn record_ds_denial_fail_open(&self) {
        self.stats.record_ds_denial_fail_open();
    }

    pub fn clear(&self) {
        self.dnskeys.clear();
        self.ds_records.clear();
        debug!("DNSSEC cache cleared");
    }
}

impl Default for DnssecCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps `map` under [`MAX_ENTRIES`] before an insert. Sweeps up to
/// [`EVICTION_BATCH_SIZE`] expired entries first (cheap, preserves live keys);
/// if the map is still full of live entries it drops one arbitrary entry so the
/// insert cannot grow the map past the ceiling. Hot zones (root, common TLDs)
/// re-populate on the next miss, so worst case is extra churn, never unbounded
/// growth.
fn evict_if_full<V, F>(map: &DashMap<Arc<str>, V>, is_expired: F)
where
    F: Fn(&V) -> bool,
{
    if map.len() < MAX_ENTRIES {
        return;
    }

    let expired: Vec<Arc<str>> = map
        .iter()
        .filter(|e| is_expired(e.value()))
        .map(|e| e.key().clone())
        .take(EVICTION_BATCH_SIZE)
        .collect();
    for k in &expired {
        map.remove(k);
    }

    if map.len() >= MAX_ENTRIES {
        let fallback = map.iter().next().map(|e| e.key().clone());
        if let Some(k) = fallback {
            map.remove(&k);
        }
    }
}
