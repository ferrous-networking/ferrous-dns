// Main DNS Cache implementation - Extracted from original cache.rs

use super::eviction::{EvictionEntry, EvictionStrategy};
use super::{CacheKey, CacheMetrics, CachedData, CachedRecord, DnssecStatus};
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// Atomic Bloom filter for fast negative lookups
struct AtomicBloom {
    bits: Vec<AtomicU64>,
    num_bits: usize,
    num_hashes: usize,
}

impl AtomicBloom {
    pub fn new(capacity: usize, fp_rate: f64) -> Self {
        let num_bits = Self::optimal_num_bits(capacity, fp_rate);
        let num_hashes = Self::optimal_num_hashes(capacity, num_bits);
        let num_words = (num_bits + 63) / 64;
        let bits = (0..num_words).map(|_| AtomicU64::new(0)).collect();
        Self {
            bits,
            num_bits,
            num_hashes,
        }
    }

    #[inline]
    pub fn check<K: Hash>(&self, key: &K) -> bool {
        let hashes = self.hash_key(key);
        hashes.iter().all(|&bit_idx| {
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            let word = self.bits[word_idx].load(AtomicOrdering::Relaxed);
            (word & (1u64 << bit_pos)) != 0
        })
    }

    #[inline]
    pub fn set<K: Hash>(&self, key: &K) {
        let hashes = self.hash_key(key);
        for &bit_idx in &hashes {
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            self.bits[word_idx].fetch_or(1u64 << bit_pos, AtomicOrdering::Relaxed);
        }
    }

    pub fn clear(&self) {
        for word in &self.bits {
            word.store(0, AtomicOrdering::Relaxed);
        }
    }

    fn hash_key<K: Hash>(&self, key: &K) -> Vec<usize> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let mut hashes = Vec::with_capacity(self.num_hashes);
        for i in 0..self.num_hashes {
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            i.hash(&mut hasher);
            let hash = hasher.finish();
            hashes.push((hash as usize) % self.num_bits);
        }
        hashes
    }

    fn optimal_num_bits(capacity: usize, fp_rate: f64) -> usize {
        let m = -1.0 * (capacity as f64) * fp_rate.ln() / (2.0_f64.ln().powi(2));
        m.ceil() as usize
    }

    fn optimal_num_hashes(capacity: usize, num_bits: usize) -> usize {
        let k = (num_bits as f64 / capacity as f64) * 2.0_f64.ln();
        k.ceil().max(1.0) as usize
    }
}

// L1 Thread-Local Cache
thread_local! {
    static L1_CACHE: RefCell<LruCache<(String, RecordType), Arc<Vec<IpAddr>>>> =
        RefCell::new(LruCache::new(NonZeroUsize::new(32).unwrap()));
}

/// DNS Cache main implementation
pub struct DnsCache {
    cache: Arc<DashMap<CacheKey, CachedRecord, FxBuildHasher>>,
    max_entries: usize,
    eviction_strategy: EvictionStrategy,
    min_threshold: Arc<RwLock<f64>>,
    refresh_threshold: f64,
    #[allow(dead_code)]
    lfuk_history_size: usize,
    batch_eviction_percentage: f64,
    adaptive_thresholds: bool,
    metrics: Arc<CacheMetrics>,
    compaction_counter: Arc<AtomicUsize>,
    use_probabilistic_eviction: bool,
    bloom: Arc<AtomicBloom>,
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
            max_entries = max_entries,
            eviction_strategy = ?eviction_strategy,
            min_threshold = min_threshold,
            refresh_threshold = refresh_threshold,
            adaptive_thresholds = adaptive_thresholds,
            "Initializing DNS cache (REFACTORED ✅)"
        );

        let cache: DashMap<CacheKey, CachedRecord, FxBuildHasher> =
            DashMap::with_capacity_and_hasher_and_shard_amount(
                max_entries,
                FxBuildHasher::default(),
                512,
            );

        let bloom_items = max_entries * 2;
        let bloom = AtomicBloom::new(bloom_items, 0.01);

        Self {
            cache: Arc::new(cache),
            max_entries,
            eviction_strategy,
            min_threshold: Arc::new(RwLock::new(min_threshold)),
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
        let key = CacheKey::new(domain.to_string(), *record_type);

        // Bloom filter pre-check
        if !self.bloom.check(&key) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        // L1 thread-local cache check
        let l1_hit = L1_CACHE.with(|cache| {
            let mut cache_mut = cache.borrow_mut();
            cache_mut.get(&(domain.to_string(), *record_type)).cloned()
        });

        if let Some(arc_data) = l1_hit {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None));
        }

        // L2 DashMap check
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            // Stale-while-revalidate
            if record.is_stale_usable() {
                if !record.refreshing.swap(true, AtomicOrdering::Acquire) {
                    // Trigger refresh externally
                }
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();

                if let CachedData::IpAddresses(ref arc_data) = record.data {
                    L1_CACHE.with(|cache| {
                        cache
                            .borrow_mut()
                            .put((domain.to_string(), *record_type), arc_data.clone());
                    });
                }

                return Some((record.data.clone(), Some(record.dnssec_status)));
            }

            // Hard expired
            if record.is_expired() && !record.is_stale_usable() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics
                    .lazy_deletions
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            // Marked for deletion
            if record.is_marked_for_deletion() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics
                    .lazy_deletions
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            record.record_hit();
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);

            if record.data.is_negative() {
                return Some((CachedData::NegativeResponse, Some(record.dnssec_status)));
            }

            if let CachedData::IpAddresses(ref arc_data) = record.data {
                L1_CACHE.with(|cache| {
                    cache
                        .borrow_mut()
                        .put((domain.to_string(), *record_type), arc_data.clone());
                });
            }

            Some((record.data.clone(), Some(record.dnssec_status)))
        } else {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            None
        }
    }

    pub fn insert(
        &self,
        domain: &str,
        record_type: &RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<DnssecStatus>,
    ) {
        if data.is_empty() {
            return;
        }

        let key = CacheKey::new(domain.to_string(), *record_type);

        // Probabilistic eviction
        if self.use_probabilistic_eviction && self.cache.len() >= self.max_entries {
            if fastrand::u32(..100) == 0 {
                self.evict_random_entry();
            }
        } else if !self.use_probabilistic_eviction && self.cache.len() >= self.max_entries {
            self.batch_evict();
        }

        let use_lfuk = self.eviction_strategy == EvictionStrategy::LFUK;
        let record = CachedRecord::new(data, ttl, record_type.clone(), use_lfuk, dnssec_status);

        self.cache.insert(key.clone(), record);
        self.bloom.set(&key);
        self.metrics
            .insertions
            .fetch_add(1, AtomicOrdering::Relaxed);

        debug!(
            domain = %domain,
            record_type = %record_type,
            ttl = ttl,
            cache_size = self.cache.len(),
            "Inserted into cache"
        );
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain.to_string(), *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }

    fn evict_random_entry(&self) {
        let len = self.cache.len();
        if len == 0 {
            return;
        }

        let random_idx = fastrand::usize(..len);
        if let Some(entry) = self.cache.iter().nth(random_idx) {
            let key = entry.key().clone();
            drop(entry);
            self.cache.remove(&key);
            self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    fn lazy_remove(&self, key: &CacheKey) {
        if let Some(entry) = self.cache.get(key) {
            entry.value().mark_for_deletion();
        }
    }

    fn batch_evict(&self) {
        let evict_count =
            ((self.max_entries as f64 * self.batch_eviction_percentage) as usize).max(1);
        let candidates = self.collect_eviction_candidates();
        let mut evicted = 0;

        let min_threshold = *self.min_threshold.read().unwrap();
        for entry in candidates.into_iter().take(evict_count) {
            if entry.score < min_threshold {
                if self.cache.remove(&entry.key).is_some() {
                    evicted += 1;
                }
            }
        }

        if evicted > 0 {
            self.metrics
                .evictions
                .fetch_add(evicted, AtomicOrdering::Relaxed);
            self.metrics
                .batch_evictions
                .fetch_add(1, AtomicOrdering::Relaxed);

            if self.adaptive_thresholds {
                self.adjust_thresholds(evicted, evict_count);
            }
        }
    }

    fn collect_eviction_candidates(&self) -> Vec<EvictionEntry> {
        let mut candidates = Vec::with_capacity(self.cache.len());

        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }

            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),
            };

            candidates.push(EvictionEntry {
                key: entry.key().clone(),
                score,
                last_access: record.last_access.load(AtomicOrdering::Relaxed),
            });
        }

        candidates.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.last_access.cmp(&b.last_access))
        });

        candidates
    }

    fn adjust_thresholds(&self, evicted: u64, target: usize) {
        let effectiveness = evicted as f64 / target as f64;
        let mut threshold = self.min_threshold.write().unwrap();

        if effectiveness < 0.5 {
            *threshold *= 0.9;
        } else if effectiveness > 0.95 {
            *threshold *= 1.05;
        }

        self.metrics
            .adaptive_adjustments
            .fetch_add(1, AtomicOrdering::Relaxed);
    }

    pub fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        let mean_score = self.calculate_mean_score();

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_expired() || record.is_marked_for_deletion() {
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),
            };

            if score >= mean_score {
                let key = entry.key();
                candidates.push((key.domain.clone(), key.record_type.clone()));
            }
        }

        candidates
    }

    fn calculate_mean_score(&self) -> f64 {
        if self.cache.is_empty() {
            return *self.min_threshold.read().unwrap();
        }

        let mut total = 0.0;
        let mut count = 0;

        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }

            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),
            };

            total += score;
            count += 1;
        }

        if count > 0 {
            total / count as f64
        } else {
            *self.min_threshold.read().unwrap()
        }
    }

    pub fn compact(&self) -> usize {
        let mut removed = 0;
        let mut to_remove = Vec::new();

        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() || record.is_expired() {
                to_remove.push(entry.key().clone());
            }
        }

        for key in to_remove {
            if self.cache.remove(&key).is_some() {
                removed += 1;
            }
        }

        if removed > 0 {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);
        }

        self.compaction_counter
            .fetch_add(1, AtomicOrdering::Relaxed);
        removed
    }

    pub fn cleanup_expired(&self) -> usize {
        self.compact()
    }

    pub fn metrics(&self) -> Arc<CacheMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn size(&self) -> usize {
        self.cache.len()
    }

    pub fn clear(&self) {
        self.cache.clear();
        self.bloom.clear();
        self.metrics.hits.store(0, AtomicOrdering::Relaxed);
        self.metrics.misses.store(0, AtomicOrdering::Relaxed);
        self.metrics.evictions.store(0, AtomicOrdering::Relaxed);
        info!("Cache cleared");
    }

    pub fn get_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain.to_string(), *record_type);
        self.cache.get(&key).map(|entry| entry.ttl)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }
}
