use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;
use rustc_hash::FxBuildHasher;

/// Cache key - Simple owned version (no lifetime issues!)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub domain: String,
    pub record_type: RecordType,
}

impl CacheKey {
    #[inline]
    pub fn new(domain: String, record_type: RecordType) -> Self {
        Self { domain, record_type }
    }
}

/// DNSSEC validation status (memory-optimized: 1 byte!)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    Unknown = 0,
    Secure = 1,
    Insecure = 2,
    Bogus = 3,
    Indeterminate = 4,
}

impl DnssecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s {
            "Secure" => Self::Secure,
            "Insecure" => Self::Insecure,
            "Bogus" => Self::Bogus,
            "Indeterminate" => Self::Indeterminate,
            _ => Self::Unknown,
        }
    }
    
    pub fn from_string(s: &str) -> Option<Self> {
        Some(Self::from_str(s))
    }
    
    pub fn from_option_string(opt: Option<String>) -> Self {
        opt.map(|s| Self::from_str(&s)).unwrap_or(Self::Unknown)
    }
}

/// Eviction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
    HitRate,
    LFU,
    LFUK,
}

impl EvictionStrategy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "lfu" => Self::LFU,
            "lfu-k" | "lfuk" => Self::LFUK,
            _ => Self::HitRate,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HitRate => "hit_rate",
            Self::LFU => "lfu",
            Self::LFUK => "lfu-k",
        }
    }
}

/// Cached DNS data
#[derive(Clone, Debug)]
pub enum CachedData {
    IpAddresses(Arc<Vec<IpAddr>>),
    CanonicalName(Arc<String>),
    NegativeResponse,
}

impl CachedData {
    pub fn is_empty(&self) -> bool {
        match self {
            CachedData::IpAddresses(addrs) => addrs.is_empty(),
            CachedData::CanonicalName(name) => name.is_empty(),
            CachedData::NegativeResponse => false,
        }
    }
    
    pub fn is_negative(&self) -> bool {
        matches!(self, CachedData::NegativeResponse)
    }
    
    pub fn as_ip_addresses(&self) -> Option<&Arc<Vec<IpAddr>>> {
        match self {
            CachedData::IpAddresses(addrs) => Some(addrs),
            _ => None,
        }
    }
    
    pub fn as_canonical_name(&self) -> Option<&Arc<String>> {
        match self {
            CachedData::CanonicalName(name) => Some(name),
            _ => None,
        }
    }
}

/// Cached record
#[derive(Debug)]
pub struct CachedRecord {
    pub data: CachedData,
    pub dnssec_status: DnssecStatus,
    pub expires_at: Instant,
    pub inserted_at: Instant,
    pub hit_count: AtomicU64,
    pub last_access: AtomicU64,
    pub ttl: u32,
    pub record_type: RecordType,
    pub access_history: Option<Box<RwLock<VecDeque<Instant>>>>,
    pub marked_for_deletion: AtomicBool,
    pub refreshing: AtomicBool,
}

impl Clone for CachedRecord {
    fn clone(&self) -> Self {
        let access_history = if self.access_history.is_some() {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };
        
        Self {
            data: self.data.clone(),
            dnssec_status: self.dnssec_status,
            expires_at: self.expires_at,
            inserted_at: self.inserted_at,
            hit_count: AtomicU64::new(self.hit_count.load(AtomicOrdering::Relaxed)),
            last_access: AtomicU64::new(self.last_access.load(AtomicOrdering::Relaxed)),
            ttl: self.ttl,
            record_type: self.record_type.clone(),
            access_history,
            marked_for_deletion: AtomicBool::new(self.marked_for_deletion.load(AtomicOrdering::Relaxed)),
            refreshing: AtomicBool::new(self.refreshing.load(AtomicOrdering::Relaxed)),
        }
    }
}

impl CachedRecord {
    pub fn new(
        data: CachedData, 
        ttl: u32,
        record_type: RecordType, 
        use_lfuk: bool,
        dnssec_status: Option<DnssecStatus>
    ) -> Self {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let access_history = if use_lfuk {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };
        
        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Unknown),
            expires_at: now + Duration::from_secs(ttl as u64),
            inserted_at: now,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_unix),
            ttl,
            record_type,
            access_history,
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
        }
    }
    
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
    
    pub fn is_stale_usable(&self) -> bool {
        let now = Instant::now();
        let age = now.duration_since(self.inserted_at).as_secs();
        let max_stale_age = (self.ttl as u64) * 2;
        
        self.is_expired() && age < max_stale_age
    }
    
    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion.store(true, AtomicOrdering::Relaxed);
    }
    
    pub fn is_marked_for_deletion(&self) -> bool {
        self.marked_for_deletion.load(AtomicOrdering::Relaxed)
    }
    
    pub fn should_refresh(&self, threshold: f64) -> bool {
        let elapsed = self.inserted_at.elapsed().as_secs_f64();
        let ttl_seconds = self.ttl as f64;
        elapsed >= (ttl_seconds * threshold)
    }
    
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, AtomicOrdering::Relaxed);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_access.store(now_unix, AtomicOrdering::Relaxed);
    }
    
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(AtomicOrdering::Relaxed) as f64;
        let age_secs = self.inserted_at.elapsed().as_secs_f64();
        
        if age_secs > 0.0 {
            hits / age_secs
        } else {
            hits
        }
    }
    
    pub fn frequency(&self) -> u64 {
        self.hit_count.load(AtomicOrdering::Relaxed)
    }
    
    pub fn lfuk_score(&self) -> f64 {
        if let Some(ref history) = self.access_history {
            if let Ok(hist) = history.try_read() {
                if hist.len() < 2 {
                    return 0.0;
                }
            
                let oldest = hist.front().unwrap();
                let newest = hist.back().unwrap();
                let timespan = newest.duration_since(*oldest).as_secs_f64();
                
                if timespan > 0.0 {
                    hist.len() as f64 / timespan
                } else {
                    hist.len() as f64
                }
            } else {
                self.hit_rate()
            }
        } else {
            0.0
        }
    }
}

#[derive(Clone)]
struct EvictionEntry {
    key: CacheKey,
    score: f64,
    last_access: u64,
}

impl PartialEq for EvictionEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for EvictionEntry {}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.last_access.cmp(&self.last_access))
    }
}

/// Lock-free Bloom filter
pub struct AtomicBloom {
    bits: Vec<AtomicU64>,
    num_bits: usize,
    num_hashes: usize,
}

impl AtomicBloom {
    pub fn new(capacity: usize, fp_rate: f64) -> Self {
        let num_bits = Self::optimal_num_bits(capacity, fp_rate);
        let num_hashes = Self::optimal_num_hashes(capacity, num_bits);
        let num_words = (num_bits + 63) / 64;
        
        let bits = (0..num_words)
            .map(|_| AtomicU64::new(0))
            .collect();
        
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
        let mut hashes = Vec::with_capacity(self.num_hashes);
        
        for i in 0..self.num_hashes {
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            i.hash(&mut hasher);
            let hash = hasher.finish();
            let bit_idx = (hash as usize) % self.num_bits;
            hashes.push(bit_idx);
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

/// DNS Cache with ULTRA-OPTIMIZATIONS
pub struct DnsCache {
    cache: Arc<DashMap<CacheKey, CachedRecord, FxBuildHasher>>,
    max_entries: usize,
    eviction_strategy: EvictionStrategy,
    min_threshold: f64,
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

// L1 Thread-Local Cache - Simple tuple key
thread_local! {
    static L1_CACHE: RefCell<LruCache<(String, RecordType), Arc<Vec<IpAddr>>>> = 
        RefCell::new(LruCache::new(NonZeroUsize::new(32).unwrap()));
}

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub insertions: AtomicU64,
    pub evictions: AtomicU64,
    pub optimistic_refreshes: AtomicU64,
    pub lazy_deletions: AtomicU64,
    pub compactions: AtomicU64,
    pub batch_evictions: AtomicU64,
    pub adaptive_adjustments: AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(AtomicOrdering::Relaxed) as f64;
        let total = hits + self.misses.load(AtomicOrdering::Relaxed) as f64;
        
        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }
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
            "Initializing OPTIMIZED DNS cache"
        );
        
        let cache: DashMap<CacheKey, CachedRecord, FxBuildHasher> = 
            DashMap::with_capacity_and_hasher_and_shard_amount(
                max_entries,
                FxBuildHasher::default(),
                512,
            );
        
        let bloom = Arc::new(AtomicBloom::new(max_entries * 2, 0.01));
        
        Self {
            cache: Arc::new(cache),
            max_entries,
            eviction_strategy,
            min_threshold,
            refresh_threshold,
            lfuk_history_size,
            batch_eviction_percentage,
            adaptive_thresholds,
            metrics: Arc::new(CacheMetrics::default()),
            compaction_counter: Arc::new(AtomicUsize::new(0)),
            use_probabilistic_eviction: true,
            bloom,
        }
    }
    
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    
    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<(CachedData, Option<DnssecStatus>)> {
        let key = CacheKey::new(domain.to_string(), *record_type);
        
        // Bloom filter pre-check
        if !self.bloom.check(&key) {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }
        
        // L1 cache check
        let l1_key = (domain.to_string(), *record_type);
        let l1_hit = L1_CACHE.with(|cache| {
            cache.borrow_mut().get(&l1_key).cloned()
        });
        
        if let Some(arc_data) = l1_hit {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None));
        }
        
        // L2 cache (DashMap)
        if let Some(entry) = self.cache.get(&key) {
            let record = entry.value();
            
            if record.is_stale_usable() {
                if !record.refreshing.swap(true, AtomicOrdering::Acquire) {
                    // Trigger refresh
                }
                
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                
                if let CachedData::IpAddresses(ref arc_data) = record.data {
                    let l1_key = (domain.to_string(), *record_type);
                    L1_CACHE.with(|cache| {
                        cache.borrow_mut().put(l1_key, arc_data.clone());
                    });
                }
                
                return Some((record.data.clone(), Some(record.dnssec_status)));
            }
            
            if record.is_expired() && !record.is_stale_usable() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }
            
            if record.is_marked_for_deletion() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }
            
            record.record_hit();
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            
            if let CachedData::IpAddresses(ref arc_data) = record.data {
                let l1_key = (domain.to_string(), *record_type);
                L1_CACHE.with(|cache| {
                    cache.borrow_mut().put(l1_key, arc_data.clone());
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
        dnssec_status: Option<DnssecStatus>
    ) {
        if data.is_empty() {
            return;
        }
        
        let key = CacheKey::new(domain.to_string(), *record_type);
        
        if self.cache.len() >= self.max_entries {
            if self.use_probabilistic_eviction {
                if fastrand::u32(..100) == 0 {
                    self.evict_weighted_random();
                }
            } else {
                self.batch_evict();
            }
        }
        
        let use_lfuk = self.eviction_strategy == EvictionStrategy::LFUK;
        let record = CachedRecord::new(data, ttl, *record_type, use_lfuk, dnssec_status);
        
        self.cache.insert(key.clone(), record);
        self.bloom.set(&key);
        
        self.metrics.insertions.fetch_add(1, AtomicOrdering::Relaxed);
    }
    
    fn evict_weighted_random(&self) -> bool {
        const SAMPLE_SIZE: usize = 5;
        
        let mut candidates: Vec<(CacheKey, f64)> = Vec::with_capacity(SAMPLE_SIZE);
        
        for _ in 0..SAMPLE_SIZE {
            let len = self.cache.len();
            if len == 0 { return false; }
            
            if let Some(entry) = self.cache.iter().nth(fastrand::usize(..len)) {
                let score = match self.eviction_strategy {
                    EvictionStrategy::HitRate => entry.value().hit_rate(),
                    EvictionStrategy::LFU => entry.value().frequency() as f64,
                    EvictionStrategy::LFUK => entry.value().lfuk_score(),
                };
                
                candidates.push((entry.key().clone(), score));
            }
        }
        
        if let Some((key, score)) = candidates.iter().min_by(|a, b| {
            a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)
        }) {
            if score < &self.min_threshold {
                self.cache.remove(key);
                self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
                return true;
            }
        }
        
        false
    }
    
    fn lazy_remove(&self, key: &CacheKey) {
        if let Some(entry) = self.cache.get(key) {
            entry.value().mark_for_deletion();
        }
    }
    
    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain.to_string(), *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }
    
    fn batch_evict(&self) {
        let evict_count = ((self.max_entries as f64 * self.batch_eviction_percentage) as usize).max(1);
        let candidates = self.collect_eviction_candidates();
        
        let mut evicted = 0;
        for entry in candidates.into_iter().take(evict_count) {
            if entry.score < self.min_threshold {
                if self.cache.remove(&entry.key).is_some() {
                    evicted += 1;
                }
            }
        }
        
        if evicted > 0 {
            self.metrics.evictions.fetch_add(evicted, AtomicOrdering::Relaxed);
            self.metrics.batch_evictions.fetch_add(1, AtomicOrdering::Relaxed);
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
            a.score.partial_cmp(&b.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.last_access.cmp(&b.last_access))
        });
        
        candidates
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
            return self.min_threshold;
        }
        
        let mut total: f64 = 0.0;
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
            self.min_threshold
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
            self.metrics.compactions.fetch_add(1, AtomicOrdering::Relaxed);
        }
        
        self.compaction_counter.fetch_add(1, AtomicOrdering::Relaxed);
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
        self.metrics.optimistic_refreshes.store(0, AtomicOrdering::Relaxed);
        self.metrics.lazy_deletions.store(0, AtomicOrdering::Relaxed);
        self.metrics.batch_evictions.store(0, AtomicOrdering::Relaxed);
        
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
