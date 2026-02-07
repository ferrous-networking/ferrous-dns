// Main DNS Cache implementation — all performance optimizations applied:
// - CompactString: inline storage for domains ≤24 bytes (no heap alloc)
// - BorrowedKey: zero-allocation bloom filter and L1 cache checks
// - Double-hash bloom filter (Kirsch-Mitzenmacker) with FxHasher
// - O(1) probabilistic eviction
// - Sampling-based batch eviction (Redis-style)

use super::eviction::{EvictionEntry, EvictionStrategy};
use super::key::BorrowedKey;
use super::{CacheKey, CacheMetrics, CachedData, CachedRecord, DnssecStatus};
use compact_str::CompactString;
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

// --- Bloom filter (zero-allocation, double-hashing) ---

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
        let (h1, h2) = Self::double_hash(key);
        for i in 0..self.num_hashes {
            let bit_idx = Self::nth_hash(h1, h2, i as u64, self.num_bits);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if (self.bits[word_idx].load(AtomicOrdering::Relaxed) & (1u64 << bit_pos)) == 0 {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn set<K: Hash>(&self, key: &K) {
        let (h1, h2) = Self::double_hash(key);
        for i in 0..self.num_hashes {
            let bit_idx = Self::nth_hash(h1, h2, i as u64, self.num_bits);
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

    #[inline]
    fn double_hash<K: Hash>(key: &K) -> (u64, u64) {
        use rustc_hash::FxHasher;
        use std::hash::Hasher;
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        let h1 = hasher.finish();
        let h2 = h1
            .wrapping_mul(0x517cc1b727220a95)
            .wrapping_add(0x6c62272e07bb0142);
        (h1, h2)
    }

    #[inline]
    fn nth_hash(h1: u64, h2: u64, i: u64, num_bits: usize) -> usize {
        h1.wrapping_add(i.wrapping_mul(h2)) as usize % num_bits
    }

    fn optimal_num_bits(capacity: usize, fp_rate: f64) -> usize {
        (-1.0 * (capacity as f64) * fp_rate.ln() / (2.0_f64.ln().powi(2))).ceil() as usize
    }

    fn optimal_num_hashes(capacity: usize, num_bits: usize) -> usize {
        ((num_bits as f64 / capacity as f64) * 2.0_f64.ln())
            .ceil()
            .max(1.0) as usize
    }
}

// --- L1 Thread-Local Cache (CompactString keys) ---

thread_local! {
    static L1_CACHE: RefCell<LruCache<(CompactString, RecordType), Arc<Vec<IpAddr>>>> =
        RefCell::new(LruCache::new(NonZeroUsize::new(32).unwrap()));
}

// --- DNS Cache ---

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
            max_entries,
            ?eviction_strategy,
            min_threshold,
            refresh_threshold,
            adaptive_thresholds,
            "Initializing DNS cache"
        );
        let cache = DashMap::with_capacity_and_hasher_and_shard_amount(
            max_entries,
            FxBuildHasher::default(),
            512,
        );
        let bloom = AtomicBloom::new(max_entries * 2, 0.01);
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
        // Zero-allocation bloom check
        let borrowed = BorrowedKey::new(domain, *record_type);
        if !self.bloom.check(&borrowed) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        // L1 thread-local cache check (CompactString key)
        let l1_hit = L1_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .get(&(CompactString::from(domain), *record_type))
                .cloned()
        });
        if let Some(arc_data) = l1_hit {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None));
        }

        // L2 DashMap check
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
                self.metrics
                    .lazy_deletions
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

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
            self.promote_to_l1(domain, record_type, record);
            Some((record.data.clone(), Some(record.dnssec_status)))
        } else {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            None
        }
    }

    #[inline]
    fn promote_to_l1(&self, domain: &str, record_type: &RecordType, record: &CachedRecord) {
        if let CachedData::IpAddresses(ref arc_data) = record.data {
            L1_CACHE.with(|cache| {
                cache.borrow_mut().put(
                    (CompactString::from(domain), *record_type),
                    arc_data.clone(),
                );
            });
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
        let key = CacheKey::new(domain, *record_type);

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
        debug!(domain = %domain, record_type = %record_type, ttl, cache_size = self.cache.len(), "Inserted into cache");
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
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

    fn lazy_remove(&self, key: &CacheKey) {
        if let Some(entry) = self.cache.get(key) {
            entry.value().mark_for_deletion();
        }
    }

    fn batch_evict(&self) {
        let evict_count =
            ((self.max_entries as f64 * self.batch_eviction_percentage) as usize).max(1);
        let candidates = self.collect_eviction_candidates(evict_count);
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

    fn collect_eviction_candidates(&self, target_count: usize) -> Vec<EvictionEntry> {
        let sample_size = (target_count * 3).min(256).max(16);
        let mut candidates = Vec::with_capacity(sample_size);
        for entry in self.cache.iter().take(sample_size) {
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }
            candidates.push(EvictionEntry {
                key: entry.key().clone(),
                score: self.compute_score(record),
                last_access: record.last_access.load(AtomicOrdering::Relaxed),
            });
        }
        candidates.sort_unstable_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.last_access.cmp(&b.last_access))
        });
        candidates
    }

    #[inline]
    fn compute_score(&self, record: &CachedRecord) -> f64 {
        match self.eviction_strategy {
            EvictionStrategy::HitRate => record.hit_rate(),
            EvictionStrategy::LFU => record.frequency() as f64,
            EvictionStrategy::LFUK => record.lfuk_score(),
        }
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
            if self.compute_score(record) >= mean_score {
                let key = entry.key();
                candidates.push((key.domain.to_string(), key.record_type.clone()));
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
            total += self.compute_score(record);
            count += 1;
        }
        if count > 0 {
            total / count as f64
        } else {
            *self.min_threshold.read().unwrap()
        }
    }

    pub fn compact(&self) -> usize {
        let mut to_remove = Vec::new();
        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() || record.is_expired() {
                to_remove.push(entry.key().clone());
            }
        }
        let mut removed = 0;
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
        let key = CacheKey::new(domain, *record_type);
        self.cache.get(&key).map(|entry| entry.ttl)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }
}
