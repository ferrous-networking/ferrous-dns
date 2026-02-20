use super::bloom::AtomicBloom;
use super::coarse_clock::coarse_now_secs;
use super::eviction::{ActiveEvictionPolicy, EvictionStrategy};
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
    pub batch_eviction_percentage: f64,
    pub adaptive_thresholds: bool,
    pub min_frequency: u64,
    pub min_lfuk_score: f64,
    pub shard_amount: usize,
    pub access_window_secs: u64,
    pub eviction_sample_size: usize,
}

pub struct DnsCache {
    pub(super) cache: Arc<DashMap<CacheKey, CachedRecord, FxBuildHasher>>,
    pub(super) max_entries: usize,
    /// Política de eviction ativa com dispatch via enum (zero-cost, sem vtable).
    /// Substituiu os campos `eviction_strategy`, `min_frequency` e `min_lfuk_score`.
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
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        let eviction_policy = ActiveEvictionPolicy::from_config(
            config.eviction_strategy,
            config.min_frequency,
            config.min_lfuk_score,
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
        let bloom = AtomicBloom::new(config.max_entries * 2, 0.01);

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
        if !self.bloom.check(&borrowed) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }

        let key = CacheKey::new(domain.as_ref(), *record_type);
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();

            let now_secs = coarse_now_secs();

            if record.is_stale_usable_at_secs(now_secs) {
                record.refreshing.swap(true, AtomicOrdering::Acquire);
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
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
        let key = CacheKey::new(domain, record_type);

        if self.cache.len() >= self.max_entries {
            self.evict_entries();
        }

        let maybe_l1 = if let CachedData::IpAddresses(ref addr) = data {
            Some(Arc::clone(addr))
        } else {
            None
        };

        let use_lfuk = self.eviction_policy.uses_access_history();
        let record = CachedRecord::new(data, ttl, record_type, use_lfuk, dnssec_status);

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
            l1_insert(domain, &record_type, addresses, ttl);
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

        let maybe_l1 = if let CachedData::IpAddresses(ref addr) = data {
            Some(Arc::clone(addr))
        } else {
            None
        };

        let record = CachedRecord::permanent(data, 365 * 24 * 60 * 60, record_type);
        self.cache.insert(key, record);

        if let Some(addresses) = maybe_l1 {
            l1_insert(domain, &record_type, addresses, 365 * 24 * 60 * 60);
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

    pub fn get_remaining_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new(domain, *record_type);
        self.cache
            .get(&key)
            .map(|entry| entry.expires_at_secs.saturating_sub(coarse_now_secs()) as u32)
    }

    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_policy.strategy()
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
            if record.permanent || record.is_marked_for_deletion() {
                return false;
            }
            let ttl = new_ttl.unwrap_or(record.ttl);
            record.expires_at_secs = now + ttl as u64;
            record.inserted_at_secs = now;
            record.ttl = ttl;
            if let Some(ds) = dnssec_status {
                record.dnssec_status = ds;
            }
            record
                .refreshing
                .store(false, std::sync::atomic::Ordering::Relaxed);

            let maybe_addresses = if let CachedData::IpAddresses(ref addr) = new_data {
                Some(Arc::clone(addr))
            } else {
                None
            };
            record.data = new_data;

            if let Some(addresses) = maybe_addresses {
                l1_insert(domain, record_type, addresses, ttl);
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
        if self.cache.is_empty() {
            return;
        }

        let now_secs = coarse_now_secs();
        let total_to_sample = count * self.eviction_sample_size;

        let mut urgent_expired: Vec<CacheKey> = Vec::new();
        let mut scored: Vec<(CacheKey, f64)> = Vec::new();
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
                let hit_count = record.hit_count.load(AtomicOrdering::Relaxed);
                let last_access = record.last_access.load(AtomicOrdering::Relaxed);
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

    /// Delega o cálculo de score à política de eviction ativa (zero-cost via enum dispatch).
    #[inline(always)]
    pub(super) fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        self.eviction_policy.compute_score(record, now_secs)
    }
}
