use super::bloom::AtomicBloom;
use super::coarse_clock::coarse_now_secs;
use super::eviction::EvictionStrategy;
use super::key::{BorrowedKey, CacheKey};
use super::l1::{l1_get, l1_insert};
use super::{CacheMetrics, CachedData, CachedRecord, DnssecStatus};
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info};

pub struct DnsCacheConfig {
    pub max_entries: usize,
    pub eviction_strategy: EvictionStrategy,
    pub min_threshold: f64,
    pub refresh_threshold: f64,
    pub lfuk_history_size: usize,
    pub batch_eviction_percentage: f64,
    pub adaptive_thresholds: bool,
    pub min_frequency: u64,
    pub min_lfuk_score: f64,
    pub shard_amount: usize,
    pub access_window_secs: u64,
}

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
    pub(super) min_frequency: u64,
    pub(super) min_lfuk_score: f64,
    pub(super) metrics: Arc<CacheMetrics>,
    pub(super) compaction_counter: Arc<AtomicUsize>,
    pub(super) use_probabilistic_eviction: bool,
    pub(super) bloom: Arc<AtomicBloom>,
    pub(super) access_window_secs: u64,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        info!(
            max_entries = config.max_entries,
            ?config.eviction_strategy,
            config.min_threshold,
            config.refresh_threshold,
            config.adaptive_thresholds,
            "Initializing DNS cache"
        );

        let cache = DashMap::with_capacity_and_hasher_and_shard_amount(
            config.max_entries,
            FxBuildHasher,
            config.shard_amount,
        );
        let bloom = AtomicBloom::new(config.max_entries * 2, 0.01);

        Self {
            cache: Arc::new(cache),
            max_entries: config.max_entries,
            eviction_strategy: config.eviction_strategy,
            min_threshold_bits: AtomicU64::new(config.min_threshold.to_bits()),
            refresh_threshold: config.refresh_threshold,
            lfuk_history_size: config.lfuk_history_size,
            batch_eviction_percentage: config.batch_eviction_percentage,
            adaptive_thresholds: config.adaptive_thresholds,
            min_frequency: config.min_frequency,
            min_lfuk_score: config.min_lfuk_score,
            metrics: Arc::new(CacheMetrics::default()),
            compaction_counter: Arc::new(AtomicUsize::new(0)),
            use_probabilistic_eviction: true,
            bloom: Arc::new(bloom),
            access_window_secs: config.access_window_secs,
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
        domain: &Arc<str>,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<DnssecStatus>, Option<u32>)> {
        let borrowed = BorrowedKey::new(domain.as_ref(), *record_type);
        if !self.bloom.check(&borrowed) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        if let Some((arc_data, remaining_ttl)) = l1_get(domain.as_ref(), record_type) {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None, Some(remaining_ttl)));
        }

        let key = CacheKey::new(domain.as_ref(), *record_type);
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            let now_secs = coarse_now_secs();

            if record.is_stale_usable_at_secs(now_secs) {
                record.refreshing.swap(true, AtomicOrdering::Acquire);
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                self.promote_to_l1(domain.as_ref(), record_type, record, now_secs);
                return Some((record.data.clone(), Some(record.dnssec_status), Some(0)));
            }

            if record.is_expired_at_secs(now_secs) {
                // Mark for deletion while holding the existing ref — avoids a
                // second DashMap lock acquisition that lazy_remove() would cause.
                record.mark_for_deletion();
                drop(entry);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            record.record_hit();
            let remaining_ttl = record.expires_at_secs.saturating_sub(now_secs) as u32;
            self.promote_to_l1(domain.as_ref(), record_type, record, now_secs);
            return Some((
                record.data.clone(),
                Some(record.dnssec_status),
                Some(remaining_ttl),
            ));
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
        let key = CacheKey::from_str(domain, record_type);

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let use_lfuk = matches!(self.eviction_strategy, EvictionStrategy::LFUK);
        let record = CachedRecord::new(data.clone(), ttl, record_type, use_lfuk, dnssec_status);

        match self.cache.entry(key) {
            dashmap::Entry::Vacant(e) => {
                self.bloom.set(e.key());
                e.insert(record);
            }
            dashmap::Entry::Occupied(mut e) => {
                e.insert(record);
            }
        }

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
        let key = CacheKey::from_str(domain, record_type);
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
        let key = CacheKey::from_str(domain, *record_type);

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
        let key = CacheKey::from_str(domain, *record_type);
        self.cache.get(&key).map(|entry| entry.ttl)
    }

    pub fn get_remaining_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::from_str(domain, *record_type);
        self.cache
            .get(&key)
            .map(|entry| entry.expires_at_secs.saturating_sub(coarse_now_secs()) as u32)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }

    pub fn access_window_secs(&self) -> u64 {
        self.access_window_secs
    }

    /// Atualiza TTL de uma entrada existente in-place, preservando `hit_count` e `last_access`.
    /// Retorna `true` se a entrada foi encontrada e atualizada, `false` caso contrário.
    pub fn refresh_record(
        &self,
        domain: &str,
        record_type: &RecordType,
        new_ttl: u32,
        new_data: CachedData,
        dnssec_status: Option<DnssecStatus>,
    ) -> bool {
        let key = CacheKey::from_str(domain, *record_type);
        let now = coarse_now_secs();

        if let Some(mut entry) = self.cache.get_mut(&key) {
            let record = entry.value_mut();
            if record.permanent || record.is_marked_for_deletion() {
                return false;
            }
            record.expires_at_secs = now + new_ttl as u64;
            record.inserted_at_secs = now;
            record.ttl = new_ttl;
            record.data = new_data.clone();
            if let Some(ds) = dnssec_status {
                record.dnssec_status = ds;
            }
            record
                .refreshing
                .store(false, std::sync::atomic::Ordering::Relaxed);

            if let CachedData::IpAddresses(ref addresses) = new_data {
                l1_insert(domain, record_type, Arc::clone(addresses), new_ttl);
            }
            true
        } else {
            false
        }
    }

    fn promote_to_l1(
        &self,
        domain: &str,
        record_type: &RecordType,
        record: &CachedRecord,
        now_secs: u64,
    ) {
        if let CachedData::IpAddresses(ref addresses) = record.data {
            let remaining_secs = match record.expires_at_secs.checked_sub(now_secs) {
                Some(r) if r > 0 => r as u32,
                _ => return,
            };

            l1_insert(domain, record_type, Arc::clone(addresses), remaining_secs);
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
        const EVICTION_SAMPLE_SIZE: usize = 8;

        if self.cache.is_empty() {
            return;
        }

        // Single clock read shared across all eviction iterations.
        let now_secs = coarse_now_secs();
        let mut total_evicted = 0usize;
        let mut last_worst_score = f64::MAX;

        for _ in 0..count {
            let mut worst_key: Option<CacheKey> = None;
            let mut worst_score = f64::MAX;
            let mut sampled = 0usize;
            // If we find an already-expired entry we evict it for free and skip
            // the score-based path entirely for this iteration.
            let mut expired_key: Option<CacheKey> = None;

            for entry in self.cache.iter() {
                let record = entry.value();
                if record.is_marked_for_deletion() {
                    continue;
                }

                // Free eviction: no scoring needed, just collect the key and break
                // so the iterator is fully dropped before we call remove().
                if record.is_expired_at_secs(now_secs) {
                    expired_key = Some(entry.key().clone());
                    break;
                }

                let score = self.compute_score(record);
                if score < worst_score {
                    worst_score = score;
                    worst_key = Some(entry.key().clone());
                }
                sampled += 1;
                if sampled >= EVICTION_SAMPLE_SIZE {
                    break;
                }
            }
            // Iterator is out of scope here — safe to acquire write locks below.

            if let Some(key) = expired_key {
                self.cache.remove(&key);
                total_evicted += 1;
            } else if let Some(key) = worst_key {
                self.cache.remove(&key);
                total_evicted += 1;
                last_worst_score = worst_score;
            }
        }

        self.metrics
            .evictions
            .fetch_add(total_evicted as u64, AtomicOrdering::Relaxed);

        if self.adaptive_thresholds && last_worst_score < f64::MAX {
            let current = self.get_threshold();
            let new_threshold = (current * 0.9) + (last_worst_score * 0.1);
            self.set_threshold(new_threshold);
        }
    }

    pub(super) fn compute_score(&self, record: &CachedRecord) -> f64 {
        match self.eviction_strategy {
            EvictionStrategy::LRU => record.last_access.load(AtomicOrdering::Relaxed) as f64,
            EvictionStrategy::LFU => {
                let hits = record.hit_count.load(AtomicOrdering::Relaxed);
                if self.min_frequency > 0 && hits < self.min_frequency {
                    -(self.min_frequency as f64 - hits as f64)
                } else {
                    hits as f64
                }
            }
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
                let now = coarse_now_secs() as f64;
                let age = record.inserted_at_secs as f64;
                let k_value = 0.5;
                let score = hits / (age.powf(k_value).max(1.0)) * (1.0 / (now - access_time + 1.0));
                if self.min_lfuk_score > 0.0 && score < self.min_lfuk_score {
                    score - self.min_lfuk_score
                } else {
                    score
                }
            }
        }
    }
}
