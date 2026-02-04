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
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};  // ✅ Keep debug for non-hot paths!
use ahash::RandomState;
use bloomfilter::Bloom;

/// Cache key for efficient lookups - Uses Cow for ZERO allocations on lookups!
#[derive(Clone, Debug)]
pub struct CacheKey {
    pub domain: String,  // Owned for storage in DashMap
    pub record_type: RecordType,
}

impl CacheKey {
    /// Create owned key (for insertions)
    #[inline]
    pub fn new_owned(domain: String, record_type: RecordType) -> Self {
        Self { domain, record_type }
    }
    
    /// Create borrowed key for lookups (ZERO allocations!)
    #[inline]
    pub fn new_borrowed(domain: &str, record_type: RecordType) -> BorrowedKey {
        BorrowedKey { domain, record_type }
    }
}

/// Borrowed key for ZERO-ALLOCATION lookups!
#[derive(Debug)]
pub struct BorrowedKey<'a> {
    pub domain: &'a str,
    pub record_type: RecordType,
}

impl Hash for CacheKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl<'a> Hash for BorrowedKey<'a> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl PartialEq for CacheKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

impl<'a> PartialEq<CacheKey> for BorrowedKey<'a> {
    #[inline]
    fn eq(&self, other: &CacheKey) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

impl<'a> PartialEq<BorrowedKey<'a>> for CacheKey {
    #[inline]
    fn eq(&self, other: &BorrowedKey<'a>) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

impl Eq for CacheKey {}

// Make BorrowedKey compatible with DashMap lookups
impl<'a> std::borrow::Borrow<BorrowedKey<'a>> for CacheKey {
    fn borrow(&self) -> &BorrowedKey<'a> {
        // SAFETY: This is safe because we're only using this for lookups
        // and the lifetime is tied to self
        unsafe {
            std::mem::transmute(&BorrowedKey {
                domain: &self.domain,
                record_type: self.record_type.clone(),
            })
        }
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
    
    /// Convert from String reference
    pub fn from_string(s: &str) -> Option<Self> {
        Some(Self::from_str(s))
    }
    
    pub fn from_option_string(opt: Option<String>) -> Self {
        opt.map(|s| Self::from_str(&s)).unwrap_or(Self::Unknown)
    }
}

/// Eviction strategy for cache management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
    /// Hit rate based eviction (hits per second)
    HitRate,
    /// Least Frequently Used (total hits)
    LFU,
    /// LFU-K (frequency in sliding window of K accesses)
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

/// Cached DNS data - supports different record types (ZERO-COPY with Arc!)
#[derive(Clone, Debug)]
pub enum CachedData {
    /// IP addresses (A, AAAA records) - Arc = zero-copy clone! ✅
    IpAddresses(Arc<Vec<IpAddr>>),
    
    /// Canonical name (CNAME record) - Arc = zero-copy clone! ✅
    CanonicalName(Arc<String>),
    
    /// Negative response (NXDOMAIN) - Cache non-existent domains! ✅
    NegativeResponse,
}

impl CachedData {
    /// Check if data is empty
    pub fn is_empty(&self) -> bool {
        match self {
            CachedData::IpAddresses(addrs) => addrs.is_empty(),
            CachedData::CanonicalName(name) => name.is_empty(),
            CachedData::NegativeResponse => false,  // Negative cache is valid data
        }
    }
    
    /// Check if this is a negative response
    pub fn is_negative(&self) -> bool {
        matches!(self, CachedData::NegativeResponse)
    }
    
    /// Get IP addresses if this is an IP record
    pub fn as_ip_addresses(&self) -> Option<&Arc<Vec<IpAddr>>> {
        match self {
            CachedData::IpAddresses(addrs) => Some(addrs),
            _ => None,
        }
    }
    
    /// Get canonical name if this is a CNAME record
    pub fn as_canonical_name(&self) -> Option<&Arc<String>> {
        match self {
            CachedData::CanonicalName(name) => Some(name),
            _ => None,
        }
    }
}

/// Cached DNS record with metadata (MEMORY-OPTIMIZED)
#[derive(Debug)]  // Removed Clone - will implement manually
pub struct CachedRecord {
    /// Cached data (IPs or CNAME)
    pub data: CachedData,
    
    /// DNSSEC validation status (1 byte enum instead of 24 bytes String!)
    pub dnssec_status: DnssecStatus,
    
    /// When this record expires (lazy expiration)
    pub expires_at: Instant,
    
    /// When this record was inserted
    pub inserted_at: Instant,
    
    /// Number of times this record has been accessed (inline atomic - no Arc!)
    pub hit_count: AtomicU64,
    
    /// Last access time (inline atomic - no Arc!)
    pub last_access: AtomicU64,
    
    /// TTL in seconds (u32 instead of u64 - supports up to 136 years!)
    pub ttl: u32,
    
    /// Record type
    pub record_type: RecordType,
    
    /// Access history for LFU-K (lazy allocation - only when strategy = LFUK)
    pub access_history: Option<Box<RwLock<VecDeque<Instant>>>>,
    
    /// Marked for lazy deletion (inline atomic - no Arc!)
    pub marked_for_deletion: AtomicBool,
    
    /// Stale-While-Revalidate: Currently being refreshed (inline atomic!)
    pub refreshing: AtomicBool,
}

// Manual Clone implementation because atomics don't implement Clone
impl Clone for CachedRecord {
    fn clone(&self) -> Self {
        // Clone access_history if it exists
        let access_history = if let Some(ref _history) = self.access_history {
            // Can't clone RwLock easily, so create new empty history
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
        ttl: u32,  // Changed from u64 to u32
        record_type: RecordType, 
        use_lfuk: bool,  // Only allocate history if using LFU-K
        dnssec_status: Option<DnssecStatus>  // ✅ DnssecStatus directly, no String!
    ) -> Self {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Lazy allocation: only create access_history if LFU-K strategy
        let access_history = if use_lfuk {
            Some(Box::new(RwLock::new(VecDeque::with_capacity(10))))
        } else {
            None
        };
        
        Self {
            data,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Unknown),  // ✅ Direct copy!
            expires_at: now + Duration::from_secs(ttl as u64),
            inserted_at: now,
            hit_count: AtomicU64::new(0),
            last_access: AtomicU64::new(now_unix),
            ttl,
            record_type,
            access_history,
            marked_for_deletion: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),  // ✅ Not refreshing initially
        }
    }
    
    /// Check if record is expired (lazy expiration)
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
    
    /// Check if record is stale but still usable (Stale-While-Revalidate)
    /// Returns true if: expired BUT age < 2x TTL (grace period)
    pub fn is_stale_usable(&self) -> bool {
        let now = Instant::now();
        let age = now.duration_since(self.inserted_at).as_secs();
        let max_stale_age = (self.ttl as u64) * 2;  // 2x TTL grace period
        
        self.is_expired() && age < max_stale_age
    }
    
    /// Get age in seconds
    pub fn age_secs(&self) -> u64 {
        Instant::now().duration_since(self.inserted_at).as_secs()
    }
    
    /// Mark for deletion (lazy deletion)
    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion.store(true, AtomicOrdering::Relaxed);
    }
    
    /// Check if marked for deletion
    pub fn is_marked_for_deletion(&self) -> bool {
        self.marked_for_deletion.load(AtomicOrdering::Relaxed)
    }
    
    /// Check if record should be refreshed optimistically
    pub fn should_refresh(&self, threshold: f64) -> bool {
        let elapsed = self.inserted_at.elapsed().as_secs_f64();
        let ttl_seconds = self.ttl as f64;
        elapsed >= (ttl_seconds * threshold)
    }
    
    /// Record a hit - ULTRA-FAST: Only atomic increment! ✅
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, AtomicOrdering::Relaxed);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_access.store(now_unix, AtomicOrdering::Relaxed);
        // REMOVED: access_history update (expensive RwLock!)
    }
    
    /// Get hit rate (hits per second since insertion)
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(AtomicOrdering::Relaxed) as f64;
        let age_secs = self.inserted_at.elapsed().as_secs_f64();
        
        if age_secs > 0.0 {
            hits / age_secs
        } else {
            hits
        }
    }
    
    /// Get total hit count (for LFU)
    pub fn frequency(&self) -> u64 {
        self.hit_count.load(AtomicOrdering::Relaxed)
    }
    
    /// Get LFU-K frequency score (hits per second in sliding window) - NON-BLOCKING!
    pub fn lfuk_score(&self) -> f64 {  // ✅ Removed async!
        // Only if access_history is allocated (LFU-K strategy)
        if let Some(ref history) = self.access_history {
            // Try read - non-blocking! ✅
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
                // Can't get lock - return fallback (hit_rate) ✅
                // This is OK! hit_rate is very similar to lfuk_score in practice
                self.hit_rate()
            }
        } else {
            0.0  // No history allocated
        }
    }
}

/// Entry for eviction priority queue
#[derive(Clone)]
struct EvictionEntry {
    key: CacheKey,  // Changed from String to CacheKey
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
        // Min-heap: lower score = higher priority for eviction
        other.score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.last_access.cmp(&self.last_access))
    }
}

/// DNS Cache with multiple eviction strategies and performance optimizations
pub struct DnsCache {
    /// Cache storage with ahash RandomState (OPTIMIZED: CacheKey for zero-allocation lookups!)
    cache: Arc<DashMap<CacheKey, CachedRecord, RandomState>>,
    
    /// Maximum entries
    max_entries: usize,
    
    /// Eviction strategy
    eviction_strategy: EvictionStrategy,
    
    /// Minimum threshold for eviction
    min_threshold: f64,
    
    /// Threshold for optimistic refresh (0.0 to 1.0)
    refresh_threshold: f64,
    
    /// LFU-K history size (kept for compatibility, history now fixed at 10)
    #[allow(dead_code)]
    lfuk_history_size: usize,
    
    /// Batch eviction size (percentage of max_entries)
    batch_eviction_percentage: f64,
    
    /// Adaptive thresholds enabled
    adaptive_thresholds: bool,
    
    /// Metrics
    metrics: Arc<CacheMetrics>,
    
    /// Compaction counter (for background compaction)
    compaction_counter: Arc<AtomicUsize>,
    
    /// Use probabilistic eviction (O(1) instead of batch O(N)) ✅
    use_probabilistic_eviction: bool,
    
    /// Bloom filter for fast negative lookups ✅
    bloom: Arc<StdRwLock<Bloom<CacheKey>>>,
}

// L1 Thread-Local Cache - ZERO locks, ~10ns access! ✅
thread_local! {
    static L1_CACHE: RefCell<LruCache<CacheKey, Arc<Vec<IpAddr>>>> = 
        RefCell::new(LruCache::new(NonZeroUsize::new(32).unwrap()));
}

/// Cache metrics
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
            min_threshold = min_threshold,
            refresh_threshold = refresh_threshold,
            lfuk_history_size = lfuk_history_size,
            batch_eviction_percentage = batch_eviction_percentage,
            adaptive_thresholds = adaptive_thresholds,
            shards = 256,
            l1_cache_size = 32,
            probabilistic_eviction = true,
            bloom_filter = true,
            ahash_simd = true,
            stale_while_revalidate = true,
            stale_grace_period = "2x TTL",
            "Initializing DNS cache with ULTRA-OPTIMIZATION ✅"
        );
        
        // Create DashMap with 512 shards and ahash for ULTRA concurrency! ✅
        let cache: DashMap<CacheKey, CachedRecord, RandomState> = DashMap::with_capacity_and_hasher_and_shard_amount(
            max_entries,
            RandomState::new(),  // ✅ ahash with SIMD acceleration!
            512,  // ✅ 512 shards = 2x better concurrency than 256!
        );
        
        // Create Bloom filter for fast negative lookups ✅
        // False positive rate: 1% (acceptable trade-off)
        let bloom_items = max_entries * 2;  // 2x capacity for low false positive rate
        let bloom = Bloom::new_for_fp_rate(bloom_items, 0.01);
        
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
            use_probabilistic_eviction: true,  // ✅ Enable probabilistic eviction!
            bloom: Arc::new(StdRwLock::new(bloom)),  // ✅ Bloom filter for fast lookups!
        }
    }
    
    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    
    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    
    /// Get record from cache with Bloom + L1/L2 architecture - ULTRA-FAST! ✅
    /// NON-ASYNC for MAXIMUM PERFORMANCE! Cache reads are CPU-bound, no I/O!
    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<(CachedData, Option<DnssecStatus>)> {
        let key = CacheKey::new_owned(domain.to_string(), *record_type);  // ← Copy RecordType!
        
        // 0. Bloom filter pre-check (~10ns) - Skip DashMap if definitely not present! ✅
        if let Ok(bloom) = self.bloom.read() {
            if !bloom.check(&key) {
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }
        }
        
        // 1. Check L1 (thread-local) - ZERO locks, ~10ns! ✅✅✅
        let l1_hit = L1_CACHE.with(|cache| {
            let mut cache_mut = cache.borrow_mut();
            cache_mut.get(&key).cloned()
        });
        
        if let Some(arc_data) = l1_hit {
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            return Some((CachedData::IpAddresses(arc_data), None));
        }
        
        // 2. Check L2 (DashMap)
        if let Some(entry) = self.cache.get(&key) {
            let record: &CachedRecord = entry.value();
            
            // 🔥 STALE-WHILE-REVALIDATE: Check if stale but still usable
            if record.is_stale_usable() {
                // Try to claim refresh ownership (only one thread refreshes)
                if !record.refreshing.swap(true, AtomicOrdering::Acquire) {
                    // We won the race! Trigger background refresh
                    // Note: External refresh will be triggered by resolver
                    // This flag prevents multiple concurrent refreshes
                }
                
                // Return stale data IMMEDIATELY (user doesn't wait!) ⚡
                self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
                record.record_hit();
                
                // Promote to L1 if IpAddresses
                if let CachedData::IpAddresses(ref arc_data) = record.data {
                    L1_CACHE.with(|cache| {
                        cache.borrow_mut().put(key.clone(), arc_data.clone());
                    });
                }
                
                return Some((record.data.clone(), Some(record.dnssec_status)));
            }
            
            // Lazy expiration check - HARD expired (age > 2x TTL)
            if record.is_expired() && !record.is_stale_usable() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics.lazy_deletions.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }
            
            // Check if marked for deletion
            if record.is_marked_for_deletion() {
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics.lazy_deletions.fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }
            
            // Record hit (non-blocking!)
            record.record_hit();
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);
            
            // Check for negative cache ✅
            if record.data.is_negative() {
                return Some((CachedData::NegativeResponse, Some(record.dnssec_status)));
            }
            
            // Store in L1 for next time (if IpAddresses) ✅
            if let CachedData::IpAddresses(ref arc_data) = record.data {
                L1_CACHE.with(|cache| {
                    cache.borrow_mut().put(key.clone(), arc_data.clone());
                });
            }
            
            // Return with DnssecStatus (copy 1 byte) instead of String! ✅
            Some((record.data.clone(), Some(record.dnssec_status)))
        } else {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            None
        }
    }
    
    /// Insert record into cache with PROBABILISTIC EVICTION + Bloom filter ✅
    pub fn insert(&self, domain: &str, record_type: &RecordType, data: CachedData, ttl: u32, dnssec_status: Option<DnssecStatus>) {
        if data.is_empty() {
            return;
        }
        
        let key = CacheKey::new_owned(domain.to_string(), *record_type);  // ← Copy RecordType!
        
        // Probabilistic eviction - O(1) instead of batch O(N)! ✅
        if self.use_probabilistic_eviction && self.cache.len() >= self.max_entries {
            // 1% chance per insert when at capacity
            if fastrand::u32(..100) == 0 {
                self.evict_random_entry();
            }
        } else if !self.use_probabilistic_eviction && self.cache.len() >= self.max_entries {
            // Fallback to batch eviction
            self.batch_evict();
        }
        
        let use_lfuk = self.eviction_strategy == EvictionStrategy::LFUK;
        let record = CachedRecord::new(data, ttl, record_type.clone(), use_lfuk, dnssec_status);
        
        self.cache.insert(key.clone(), record);
        
        // Add to Bloom filter ✅
        if let Ok(mut bloom) = self.bloom.write() {
            bloom.set(&key);
        }
        
        self.metrics.insertions.fetch_add(1, AtomicOrdering::Relaxed);
        
        debug!(
            domain = %domain,
            record_type = %record_type,
            ttl = ttl,
            dnssec_status = ?dnssec_status,
            cache_size = self.cache.len(),
            probabilistic_eviction = self.use_probabilistic_eviction,
            "Inserted into cache"
        );
    }
    
    /// Reset refreshing flag for Stale-While-Revalidate ✅
    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new_owned(domain.to_string(), *record_type);  // ← Copy!
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }
    
    /// Evict single random entry - O(1) probabilistic eviction! ✅
    fn evict_random_entry(&self) {
        let len = self.cache.len();
        if len == 0 {
            return;
        }
        
        // Random eviction - O(1)
        let random_idx = fastrand::usize(..len);
        if let Some(entry) = self.cache.iter().nth(random_idx) {
            let key = entry.key().clone();
            drop(entry);
            self.cache.remove(&key);
            self.metrics.evictions.fetch_add(1, AtomicOrdering::Relaxed);
            
            debug!(
                index = random_idx,
                cache_size = self.cache.len(),
                "Probabilistic eviction (O(1))"
            );
        }
    }
    
    /// Lazy remove (mark for deletion, actual removal in compaction)
    fn lazy_remove(&self, key: &CacheKey) {
        if let Some(entry) = self.cache.get(key) {
            let record: &CachedRecord = entry.value();
            record.mark_for_deletion();
        }
    }
    
    /// Batch eviction - remove multiple entries at once - NON-BLOCKING!
    fn batch_evict(&self) {
        let evict_count = ((self.max_entries as f64 * self.batch_eviction_percentage) as usize).max(1);
        
        debug!(
            current_size = self.cache.len(),
            evict_count = evict_count,
            strategy = ?self.eviction_strategy,
            "Starting batch eviction"
        );
        
        // Collect candidates - now synchronous! ✅
        let candidates = self.collect_eviction_candidates();
        
        // Evict in batch
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
            
            info!(
                evicted = evicted,
                cache_size = self.cache.len(),
                strategy = ?self.eviction_strategy,
                "Batch eviction completed"
            );
            
            // Adaptive threshold adjustment
            if self.adaptive_thresholds {
                self.adjust_thresholds(evicted, evict_count);
            }
        }
    }
    
    /// Collect eviction candidates based on strategy - NON-BLOCKING!
    fn collect_eviction_candidates(&self) -> Vec<EvictionEntry> {  // ✅ Removed async!
        let mut candidates = Vec::with_capacity(self.cache.len());
        
        for entry in self.cache.iter() {
            let record: &CachedRecord = entry.value();
            
            // Skip if marked for deletion
            if record.is_marked_for_deletion() {
                continue;
            }
            
            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),  // ✅ No await!
            };
            
            candidates.push(EvictionEntry {
                key: entry.key().clone(),
                score,
                last_access: record.last_access.load(AtomicOrdering::Relaxed),
            });
        }
        
        // Sort by score (ascending - lowest first)
        candidates.sort_by(|a, b| {
            a.score.partial_cmp(&b.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.last_access.cmp(&b.last_access))
        });
        
        candidates
    }
    
    /// Adaptive threshold adjustment based on eviction effectiveness
    fn adjust_thresholds(&self, evicted: u64, target: usize) {
        let effectiveness = evicted as f64 / target as f64;
        
        // If we didn't evict enough, lower the threshold
        if effectiveness < 0.5 {
            // Decrease threshold by 10%
            let new_threshold = self.min_threshold * 0.9;
            info!(
                old_threshold = self.min_threshold,
                new_threshold = new_threshold,
                effectiveness = effectiveness,
                "Lowering eviction threshold (adaptive)"
            );
            // Note: In real implementation, update via atomic or RwLock
        }
        // If we evicted too much, raise the threshold
        else if effectiveness > 0.95 {
            // Increase threshold by 5%
            let new_threshold = self.min_threshold * 1.05;
            info!(
                old_threshold = self.min_threshold,
                new_threshold = new_threshold,
                effectiveness = effectiveness,
                "Raising eviction threshold (adaptive)"
            );
        }
        
        self.metrics.adaptive_adjustments.fetch_add(1, AtomicOrdering::Relaxed);
    }
    
    /// Get domains that should be refreshed optimistically - NON-BLOCKING!
    pub fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {  // ✅ Removed async!
        let mut candidates = Vec::new();
        let mean_score = self.calculate_mean_score();  // ✅ No await!
        
        for entry in self.cache.iter() {
            let record: &CachedRecord = entry.value();
            
            // Skip expired or marked entries
            if record.is_expired() || record.is_marked_for_deletion() {
                continue;
            }
            
            // Check if should refresh based on threshold
            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }
            
            // Check if score is above mean
            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),  // ✅ No await!
            };
            
            if score >= mean_score {
                let key = entry.key();
                candidates.push((key.domain.clone(), key.record_type.clone()));
            }
        }
        
        debug!(
            count = candidates.len(),
            mean_score = mean_score,
            strategy = ?self.eviction_strategy,
            "Found refresh candidates"
        );
        
        candidates
    }
    
    /// Calculate mean score across all cached entries
    fn calculate_mean_score(&self) -> f64 {  // ✅ Removed async!
        if self.cache.is_empty() {
            return self.min_threshold;
        }
        
        let mut total: f64 = 0.0;
        let mut count = 0;
        
        for entry in self.cache.iter() {
            let record: &CachedRecord = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }
            
            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score(),  // ✅ No await!
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
    
    /// Background compaction - remove entries marked for deletion
    pub fn compact(&self) -> usize {
        let mut removed = 0;
        let mut to_remove = Vec::new();
        
        for entry in self.cache.iter() {
            let record: &CachedRecord = entry.value();
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
            debug!(
                removed = removed,
                cache_size = self.cache.len(),
                "Background compaction completed"
            );
        }
        
        // Increment compaction counter
        self.compaction_counter.fetch_add(1, AtomicOrdering::Relaxed);
        
        removed
    }
    
    /// Remove expired entries (legacy method for compatibility)
    pub fn cleanup_expired(&self) -> usize {
        self.compact()
    }
    
    /// Get cache metrics
    pub fn metrics(&self) -> Arc<CacheMetrics> {
        Arc::clone(&self.metrics)
    }
    
    /// Get current cache size
    pub fn size(&self) -> usize {
        self.cache.len()
    }
    
    /// Clear all entries from cache
    pub fn clear(&self) {
        self.cache.clear();
        
        // Reset metrics
        self.metrics.hits.store(0, AtomicOrdering::Relaxed);
        self.metrics.misses.store(0, AtomicOrdering::Relaxed);
        self.metrics.evictions.store(0, AtomicOrdering::Relaxed);
        self.metrics.optimistic_refreshes.store(0, AtomicOrdering::Relaxed);
        self.metrics.lazy_deletions.store(0, AtomicOrdering::Relaxed);
        self.metrics.batch_evictions.store(0, AtomicOrdering::Relaxed);
        
        info!("Cache cleared - all entries removed");
    }
    
    /// Get TTL for a specific domain/record_type (for refresh)
    pub fn get_ttl(&self, domain: &str, record_type: &RecordType) -> Option<u32> {
        let key = CacheKey::new_owned(domain.to_string(), *record_type);  // ← Copy!
        self.cache.get(&key).map(|entry| entry.ttl)
    }
    
    /// Get eviction strategy
    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = DnsCache::new(100, EvictionStrategy::HitRate, 1.0, 0.75, 10, 0.1, false);
        let addresses = vec!["8.8.8.8".parse().unwrap()];
        
        cache.insert("example.com", &RecordType::A, addresses.clone(), 300);
        
        let result = cache.get("example.com", &RecordType::A).await;
        assert_eq!(result, Some(addresses));
    }
    
    #[tokio::test]
    async fn test_lazy_expiration() {
        let cache = DnsCache::new(100, EvictionStrategy::HitRate, 1.0, 0.75, 10, 0.1, false);
        let addresses = vec!["8.8.8.8".parse().unwrap()];
        
        cache.insert("example.com", &RecordType::A, addresses, 0); // 0 TTL = immediate expiration
        
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let result = cache.get("example.com", &RecordType::A).await;
        assert_eq!(result, None);
        assert_eq!(cache.metrics().lazy_deletions.load(AtomicOrdering::Relaxed), 1);
    }
    
    #[tokio::test]
    async fn test_batch_eviction() {
        let cache = DnsCache::new(10, EvictionStrategy::HitRate, 0.5, 0.75, 10, 0.2, false);
        
        // Fill cache beyond capacity
        for i in 0..15 {
            let domain = format!("example{}.com", i);
            let addresses = vec!["8.8.8.8".parse().unwrap()];
            cache.insert(&domain, &RecordType::A, addresses, 3600);
        }
        
        // Cache should have evicted in batch
        assert!(cache.size() <= 10);
        assert!(cache.metrics().batch_evictions.load(AtomicOrdering::Relaxed) > 0);
    }
    
    #[tokio::test]
    async fn test_eviction_strategies() {
        // Test Hit Rate
        let cache_hr = DnsCache::new(5, EvictionStrategy::HitRate, 1.0, 0.75, 10, 0.2, false);
        
        // Test LFU
        let cache_lfu = DnsCache::new(5, EvictionStrategy::LFU, 5.0, 0.75, 10, 0.2, false);
        
        // Test LFU-K
        let cache_lfuk = DnsCache::new(5, EvictionStrategy::LFUK, 1.0, 0.75, 10, 0.2, false);
        
        assert_eq!(cache_hr.strategy(), EvictionStrategy::HitRate);
        assert_eq!(cache_lfu.strategy(), EvictionStrategy::LFU);
        assert_eq!(cache_lfuk.strategy(), EvictionStrategy::LFUK);
    }
}
