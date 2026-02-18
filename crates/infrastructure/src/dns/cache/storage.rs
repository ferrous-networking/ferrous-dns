use super::bloom::AtomicBloom;
use super::eviction::{EvictionEntry, EvictionStrategy};
use super::key::{BorrowedKey, CacheKey};
use super::l1::{l1_get, l1_insert};
use super::{CacheMetrics, CachedData, CachedRecord, DnssecStatus};
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info};

pub struct DnsCache {
    pub(super) cache: Arc<DashMap<CacheKey, CachedRecord, FxBuildHasher>>,
    pub(super) max_entries: usize,
    pub(super) eviction_strategy: EvictionStrategy,
    pub(super) min_threshold_bits: AtomicU64,
    pub(super) refresh_threshold: f64,
    #[allow(dead_code)]
    pub(super) lfuk_history_size: usize,
    pub(super) batch_eviction_percentage: f64,
    pub(super) adaptive_thresholds: bool,
    pub(super) metrics: Arc<CacheMetrics>,
    pub(super) compaction_counter: Arc<AtomicUsize>,
    pub(super) use_probabilistic_eviction: bool,
    pub(super) bloom: Arc<AtomicBloom>,
}

impl DnsCache {
    pub fn new(
        max_entries: usize,
        eviction_strategy: EvictionStrategy,
        min_threshold: f64,
        refresh_threshold: f64,
        lfuk_history_size: usize,
        batch_eviction_percentage: f64,
        adaptive_thresholds: bool,
    ) -> Self {
        info!(
            max_entries,
            ?eviction_strategy,
            min_threshold,
            refresh_threshold,
            adaptive_thresholds,
            "Initializing DNS cache"
        );

        let cache =
            DashMap::with_capacity_and_hasher_and_shard_amount(max_entries, FxBuildHasher, 512);
        let bloom = AtomicBloom::new(max_entries * 2, 0.01);

        Self {
            cache: Arc::new(cache),
            max_entries,
            eviction_strategy,
            min_threshold_bits: AtomicU64::new(min_threshold.to_bits()),
            refresh_threshold,
            lfuk_history_size,
            batch_eviction_percentage,
            adaptive_thresholds,
            metrics: Arc::new(CacheMetrics::default()),
            compaction_counter: Arc::new(AtomicUsize::new(0)),
            use_probabilistic_eviction: true,
            bloom: Arc::new(bloom),
        }
    }

    pub(super) fn get_threshold(&self) -> f64 {
        let bits = self.min_threshold_bits.load(AtomicOrdering::Relaxed);
        f64::from_bits(bits)
    }

    fn set_threshold(&self, value: f64) {
        self.min_threshold_bits
            .store(value.to_bits(), AtomicOrdering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn get(
        &self,
        domain: &str,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<DnssecStatus>)> {
        let borrowed = BorrowedKey::new(domain, *record_type);
        if !self.bloom.check(&borrowed) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        if let Some(arc_data) = l1_get(domain, record_type) {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None));
        }

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            if record.is_stale_usable() {
                if !record.refreshing.swap(true, AtomicOrdering::Acquire) {}
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                self.promote_to_l1(domain, record_type, record);
                return Some((record.data.clone(), Some(record.dnssec_status)));
            }

            if record.is_expired() && !record.is_stale_usable() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            if !record.is_expired() {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                self.promote_to_l1(domain, record_type, record);
                return Some((record.data.clone(), Some(record.dnssec_status)));
            }
        }

        self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
        None
    }

    pub fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<DnssecStatus>,
    ) {
        let key = CacheKey::new(domain, record_type);
        self.bloom.set(&key);

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let use_lfuk = matches!(self.eviction_strategy, EvictionStrategy::LFUK);
        let record = CachedRecord::new(data.clone(), ttl, record_type, use_lfuk, dnssec_status);
        self.cache.insert(key, record);

        if let CachedData::IpAddresses(ref addresses) = data {
            l1_insert(domain, &record_type, Arc::clone(addresses), ttl);
        }

        debug!(
            domain = %domain,
            record_type = %record_type,
            ttl,
            "Inserted record into cache"
        );
    }

    pub fn insert_permanent(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        _dnssec_status: Option<DnssecStatus>,
    ) {
        let key = CacheKey::new(domain, record_type);
        self.bloom.set(&key);

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let record = CachedRecord::permanent(data.clone(), 365 * 24 * 60 * 60, record_type);
        self.cache.insert(key, record);

        if let CachedData::IpAddresses(ref addresses) = data {
            l1_insert(
                domain,
                &record_type,
                Arc::clone(addresses),
                365 * 24 * 60 * 60,
            );
        }
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType) -> bool {
        let key = CacheKey::new(domain, *record_type);

        if self.cache.remove(&key).is_some() {
            self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
            info!(domain = %domain, record_type = %record_type, "Removed record from cache");
            true
        } else {
            false
        }
    }

    pub fn clear(&self) {
        self.cache.clear();
        self.bloom.clear();
        self.metrics.hits.store(0, AtomicOrdering::Relaxed);
        self.metrics.misses.store(0, AtomicOrdering::Relaxed);
        self.metrics.evictions.store(0, AtomicOrdering::Relaxed);
        info!("Cache cleared");
    }

    pub fn metrics(&self) -> Arc<CacheMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn size(&self) -> usize {
        self.cache.len()
    }

    pub fn get_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain, *record_type);
        self.cache.get(&key).map(|entry| entry.ttl)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }

    fn promote_to_l1(&self, domain: &str, record_type: &RecordType, record: &CachedRecord) {
        if let CachedData::IpAddresses(ref addresses) = record.data {
            l1_insert(domain, record_type, Arc::clone(addresses), record.ttl);
        }
    }

    fn lazy_remove(&self, key: &CacheKey) {
        if let Some(entry) = self.cache.get(key) {
            entry.value().mark_for_deletion();
        }
    }

    fn evict_random_entry(&self) {
        if let Some(entry) = self.cache.iter().next() {
            let key = entry.key().clone();
            drop(entry);
            self.cache.remove(&key);
            self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    fn evict_entries(&self) {
        let num_to_evict = ((self.max_entries as f64) * self.batch_eviction_percentage) as usize;
        let num_to_evict = num_to_evict.max(1);

        if self.use_probabilistic_eviction && self.cache.len() > self.max_entries / 2 {
            self.evict_by_strategy(num_to_evict);
        } else {
            for _ in 0..num_to_evict {
                self.evict_random_entry();
            }
        }
    }

    fn evict_by_strategy(&self, count: usize) {
        let mut candidates: Vec<EvictionEntry> = self
            .cache
            .iter()
            .filter_map(|entry| {
                let record = entry.value();
                if record.is_marked_for_deletion() {
                    return None;
                }
                let score = self.compute_score(record);
                let last_access = record.last_access.load(AtomicOrdering::Relaxed);
                Some(EvictionEntry {
                    key: entry.key().clone(),
                    score,
                    last_access,
                })
            })
            .collect();

        if candidates.is_empty() {
            self.evict_random_entry();
            return;
        }

        candidates.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let threshold = self.get_threshold();
        let evicted_count = candidates
            .iter()
            .take(count)
            .filter(|candidate| candidate.score < threshold)
            .filter_map(|candidate| self.cache.remove(&candidate.key))
            .count();

        if evicted_count < count {
            for _ in 0..(count - evicted_count) {
                self.evict_random_entry();
            }
        }

        self.metrics
            .evictions
            .fetch_add(evicted_count as u64, AtomicOrdering::Relaxed);

        if self.adaptive_thresholds && !candidates.is_empty() {
            self.adjust_threshold(&candidates);
        }
    }

    pub(super) fn compute_score(&self, record: &CachedRecord) -> f64 {
        match self.eviction_strategy {
            EvictionStrategy::LRU => record.last_access.load(AtomicOrdering::Relaxed) as f64,
            EvictionStrategy::LFU => record.hit_count.load(AtomicOrdering::Relaxed) as f64,
            EvictionStrategy::HitRate => {
                let hits = record.hit_count.load(AtomicOrdering::Relaxed);
                let total = hits + 1;
                if total == 0 {
                    0.0
                } else {
                    (hits as f64) / (total as f64)
                }
            }
            EvictionStrategy::LFUK => {
                let access_time = record.last_access.load(AtomicOrdering::Relaxed) as f64;
                let hits = record.hit_count.load(AtomicOrdering::Relaxed) as f64;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as f64;
                let inserted_unix = record.inserted_at.elapsed().as_secs() as f64;
                let age = now - inserted_unix;
                let k_value = 0.5;
                hits / (age.powf(k_value).max(1.0)) * (1.0 / (now - access_time + 1.0))
            }
        }
    }

    fn adjust_threshold(&self, candidates: &[EvictionEntry]) {
        if candidates.is_empty() {
            return;
        }

        let sorted: Vec<f64> = candidates.iter().map(|c| c.score).collect();
        let median_index = sorted.len() / 2;
        let new_threshold = sorted[median_index];
        self.set_threshold(new_threshold);
    }
}
