use super::bloom::AtomicBloom;
use super::coarse_clock::coarse_now_secs;
use super::eviction::{ActiveEvictionPolicy, EvictionStrategy};
use super::key::{BorrowedKey, CacheKey};
use super::l1::{l1_clear, l1_get, l1_insert};
use super::negative_cache::NegativeDnsCache;
use super::port::DnsCacheAccess;
use super::{CacheMetrics, CachedData, CachedRecord, DnssecStatus};
use dashmap::{DashMap, DashSet};
use ferrous_dns_domain::RecordType;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info};

const BLOOM_TARGET_FP_RATE: f64 = 0.01;
const PERMANENT_TTL_SECS: u32 = 365 * 24 * 60 * 60;
const STALE_SERVE_TTL: u32 = 2;
const MIN_CACHE_TTL_SECS: u32 = 1;
const MAX_CACHE_TTL_SECS: u32 = 86_400;

fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(MIN_CACHE_TTL_SECS, MAX_CACHE_TTL_SECS)
}

pub struct DnsCacheConfig {
    pub max_entries: usize,
    pub eviction_strategy: EvictionStrategy,
    pub min_threshold: f64,
    pub refresh_threshold: f64,
    pub batch_eviction_percentage: f64,
    pub adaptive_thresholds: bool,
    pub min_frequency: u64,
    pub min_lfuk_score: f64,
    pub shard_amount: usize,
    pub access_window_secs: u64,
    pub eviction_sample_size: usize,
    pub lfuk_k_value: f64,
    pub refresh_sample_rate: f64,
}

pub struct DnsCache {
    pub(super) cache: Arc<DashMap<CacheKey, CachedRecord, FxBuildHasher>>,
    pub(super) max_entries: usize,
    pub(super) eviction_policy: ActiveEvictionPolicy,
    pub(super) min_threshold_bits: AtomicU64,
    pub(super) refresh_threshold: f64,
    pub(super) batch_eviction_percentage: f64,
    pub(super) adaptive_thresholds: bool,
    pub(super) metrics: Arc<CacheMetrics>,
    pub(super) compaction_counter: Arc<AtomicUsize>,
    pub(super) use_probabilistic_eviction: bool,
    pub(super) bloom: Arc<AtomicBloom>,
    pub(super) access_window_secs: u64,
    pub(super) eviction_sample_size: usize,
    pub(super) refresh_sample_period: u64,
    pub(super) negative: NegativeDnsCache,
    pub(crate) eviction_pending: AtomicBool,
    permanent_keys: Arc<DashSet<CacheKey, FxBuildHasher>>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        let eviction_policy = ActiveEvictionPolicy::from_config(
            config.eviction_strategy,
            config.min_frequency,
            config.min_lfuk_score,
            config.lfuk_k_value,
        );

        info!(
            max_entries = config.max_entries,
            eviction_strategy = eviction_policy.strategy().as_str(),
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
        let bloom = AtomicBloom::new(config.max_entries * 2, BLOOM_TARGET_FP_RATE);

        Self {
            cache: Arc::new(cache),
            max_entries: config.max_entries,
            eviction_policy,
            min_threshold_bits: AtomicU64::new(config.min_threshold.to_bits()),
            refresh_threshold: config.refresh_threshold,
            batch_eviction_percentage: config.batch_eviction_percentage,
            adaptive_thresholds: config.adaptive_thresholds,
            metrics: Arc::new(CacheMetrics::default()),
            compaction_counter: Arc::new(AtomicUsize::new(0)),
            use_probabilistic_eviction: true,
            bloom: Arc::new(bloom),
            access_window_secs: config.access_window_secs,
            eviction_sample_size: config.eviction_sample_size.max(1),
            refresh_sample_period: {
                let r = config.refresh_sample_rate.clamp(0.001, 1.0);
                (1.0 / r).ceil() as u64
            },
            negative: NegativeDnsCache::new(config.max_entries),
            eviction_pending: AtomicBool::new(false),
            permanent_keys: Arc::new(DashSet::with_hasher(FxBuildHasher)),
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
        if let Some((arc_data, remaining_ttl)) = l1_get(domain.as_ref(), record_type) {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None, Some(remaining_ttl)));
        }

        let borrowed = BorrowedKey::new(domain.as_ref(), *record_type);
        let in_bloom = self.bloom.check(&borrowed);
        let key = CacheKey::new(domain.as_ref(), *record_type);

        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            let now_secs = coarse_now_secs();

            if record.is_stale_usable_at_secs(now_secs) {
                record.try_set_refreshing();
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                return Some((
                    record.data.clone(),
                    Some(record.dnssec_status),
                    Some(STALE_SERVE_TTL),
                ));
            }

            if record.is_expired_at_secs(now_secs) {
                record.mark_for_deletion();
                drop(entry);
            } else {
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                let remaining_ttl = record.expires_at_secs.saturating_sub(now_secs) as u32;
                if !in_bloom {
                    self.bloom.set(&key);
                }
                self.promote_to_l1(domain.as_ref(), record_type, record, now_secs);
                return Some((
                    record.data.clone(),
                    Some(record.dnssec_status),
                    Some(remaining_ttl),
                ));
            }
        }

        if let Some(remaining_ttl) = self.negative.get(domain.as_ref(), record_type) {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::NegativeResponse, None, Some(remaining_ttl)));
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
        let ttl = clamp_ttl(ttl);

        if data.is_negative() {
            self.negative.insert(domain, record_type, ttl);
            return;
        }

        let key = CacheKey::new(domain, record_type);

        if self.cache.len() >= self.max_entries {
            self.eviction_pending.store(true, AtomicOrdering::Relaxed);
        }

        let maybe_l1 = if let CachedData::IpAddresses(ref addr) = data {
            Some(Arc::clone(addr))
        } else {
            None
        };

        let record = CachedRecord::new(data, ttl, record_type, dnssec_status);
        let expires_secs = record.expires_at_secs;

        match self.cache.entry(key) {
            dashmap::Entry::Vacant(e) => {
                self.bloom.set(e.key());
                e.insert(record);
            }
            dashmap::Entry::Occupied(mut e) => {
                e.insert(record);
            }
        }

        if let Some(addresses) = maybe_l1 {
            l1_insert(domain, &record_type, addresses, expires_secs);
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
        self.permanent_keys.insert(key.clone());

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let maybe_l1 = if let CachedData::IpAddresses(ref addr) = data {
            Some(Arc::clone(addr))
        } else {
            None
        };

        let record = CachedRecord::permanent(data, PERMANENT_TTL_SECS, record_type);
        self.cache.insert(key, record);

        if let Some(addresses) = maybe_l1 {
            l1_insert(domain, &record_type, addresses, u64::MAX);
        }
    }

    pub fn remove(&self, domain: &str, record_type: &RecordType) -> bool {
        let key = CacheKey::new(domain, *record_type);

        if self.cache.remove(&key).is_some() {
            self.permanent_keys.remove(&key);
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
        self.negative.clear();
        self.permanent_keys.clear();
        l1_clear();
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

    pub fn get_remaining_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain, *record_type);
        self.cache
            .get(&key)
            .map(|entry| entry.expires_at_secs.saturating_sub(coarse_now_secs()) as u32)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_policy.strategy()
    }

    pub fn rotate_bloom(&self) {
        self.bloom.rotate();
        for key in self.permanent_keys.iter() {
            self.bloom.set(key.key());
        }
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
        new_ttl: Option<u32>,
        new_data: CachedData,
        dnssec_status: Option<DnssecStatus>,
    ) -> bool {
        let key = CacheKey::new(domain, *record_type);
        let now = coarse_now_secs();

        if let Some(mut entry) = self.cache.get_mut(&key) {
            let record = entry.value_mut();
            if record.is_permanent() || record.is_marked_for_deletion() {
                return false;
            }
            let ttl = new_ttl.unwrap_or(record.ttl);
            record.expires_at_secs = now + ttl as u64;
            record.inserted_at_secs = now;
            record.ttl = ttl;
            if let Some(ds) = dnssec_status {
                record.dnssec_status = ds;
            }
            record.clear_refreshing();

            let maybe_addresses = if let CachedData::IpAddresses(ref addr) = new_data {
                Some(Arc::clone(addr))
            } else {
                None
            };
            record.data = new_data;

            if let Some(addresses) = maybe_addresses {
                l1_insert(domain, record_type, addresses, record.expires_at_secs);
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
            if record.expires_at_secs <= now_secs {
                return;
            }
            l1_insert(
                domain,
                record_type,
                Arc::clone(addresses),
                record.expires_at_secs,
            );
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

    pub fn evict_entries(&self) {
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
        if self.cache.is_empty() {
            return;
        }

        let now_secs = coarse_now_secs();
        let total_to_sample = count * self.eviction_sample_size;

        let mut urgent_expired: Vec<CacheKey> = Vec::with_capacity(count);
        let mut scored: Vec<(CacheKey, f64)> = Vec::with_capacity(total_to_sample);
        let mut sampled = 0usize;

        for entry in self.cache.iter() {
            if sampled >= total_to_sample {
                break;
            }
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }

            if record.is_expired_at_secs(now_secs) {
                let hit_count = record.counters.hit_count.load(AtomicOrdering::Relaxed);
                let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
                let within_window = hit_count > 0
                    && now_secs.saturating_sub(last_access) <= self.access_window_secs;

                if !within_window {
                    let score = self.compute_score(record, now_secs);
                    if score < 0.0 {
                        urgent_expired.push(entry.key().clone());
                        sampled += 1;
                        continue;
                    }
                }
            }

            let score = self.compute_score(record, now_secs);
            scored.push((entry.key().clone(), score));
            sampled += 1;
        }

        scored.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut total_evicted = 0usize;
        let mut last_worst_score = f64::MAX;

        for key in urgent_expired.into_iter().take(count) {
            self.cache.remove(&key);
            total_evicted += 1;
        }

        for (key, score) in scored.into_iter().take(count.saturating_sub(total_evicted)) {
            self.cache.remove(&key);
            total_evicted += 1;
            last_worst_score = score;
        }

        self.metrics
            .evictions
            .fetch_add(total_evicted as u64, AtomicOrdering::Relaxed);

        if self.adaptive_thresholds && last_worst_score < f64::MAX {
            let current = self.get_threshold();
            self.set_threshold((current * 0.9) + (last_worst_score * 0.1));
        }
    }

    #[inline(always)]
    pub(super) fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        self.eviction_policy.compute_score(record, now_secs)
    }
}

impl DnsCacheAccess for DnsCache {
    fn get(
        &self,
        domain: &Arc<str>,
        record_type: &RecordType,
    ) -> Option<(CachedData, Option<DnssecStatus>, Option<u32>)> {
        DnsCache::get(self, domain, record_type)
    }

    fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        data: CachedData,
        ttl: u32,
        dnssec_status: Option<DnssecStatus>,
    ) {
        DnsCache::insert(self, domain, record_type, data, ttl, dnssec_status);
    }
}
