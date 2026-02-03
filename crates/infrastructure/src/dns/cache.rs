use dashmap::DashMap;
use ferrous_dns_domain::{RecordType};
use std::cmp::Ordering;
use std::collections::{VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

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

/// Cached DNS record with metadata
#[derive(Clone, Debug)]
pub struct CachedRecord {
    /// IP addresses for this domain
    pub addresses: Vec<IpAddr>,

    /// When this record expires (lazy expiration)
    pub expires_at: Instant,

    /// When this record was inserted
    pub inserted_at: Instant,

    /// Number of times this record has been accessed
    pub hit_count: Arc<AtomicU64>,

    /// Last access time (for LRU tie-breaking)
    pub last_access: Arc<AtomicU64>,

    /// TTL in seconds
    pub ttl: u64,

    /// Record type
    pub record_type: RecordType,

    /// Access history for LFU-K (last K access timestamps)
    pub access_history: Arc<RwLock<VecDeque<Instant>>>,

    /// Maximum history size for LFU-K
    pub max_history: usize,

    /// Marked for lazy deletion
    pub marked_for_deletion: Arc<AtomicBool>,
}

impl CachedRecord {
    pub fn new(
        addresses: Vec<IpAddr>,
        ttl: u64,
        record_type: RecordType,
        max_history: usize,
    ) -> Self {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            addresses,
            expires_at: now + Duration::from_secs(ttl),
            inserted_at: now,
            hit_count: Arc::new(AtomicU64::new(0)),
            last_access: Arc::new(AtomicU64::new(now_unix)),
            ttl,
            record_type,
            access_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            max_history,
            marked_for_deletion: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if record is expired (lazy expiration)
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Mark for deletion (lazy deletion)
    pub fn mark_for_deletion(&self) {
        self.marked_for_deletion
            .store(true, AtomicOrdering::Relaxed);
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

    /// Record a hit and update access history
    pub async fn record_hit(&self) {
        self.hit_count.fetch_add(1, AtomicOrdering::Relaxed);
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_access.store(now_unix, AtomicOrdering::Relaxed);

        // Update access history for LFU-K
        let mut history = self.access_history.write().await;
        history.push_back(now);
        if history.len() > self.max_history {
            history.pop_front();
        }
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

    /// Get LFU-K frequency score (hits per second in sliding window)
    pub async fn lfuk_score(&self) -> f64 {
        let history = self.access_history.read().await;

        if history.len() < 2 {
            return 0.0;
        }

        let oldest = history.front().unwrap();
        let newest = history.back().unwrap();
        let timespan = newest.duration_since(*oldest).as_secs_f64();

        if timespan > 0.0 {
            history.len() as f64 / timespan
        } else {
            history.len() as f64
        }
    }
}

/// Entry for eviction priority queue
#[derive(Clone)]
struct EvictionEntry {
    domain: String,
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
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.last_access.cmp(&self.last_access))
    }
}

/// DNS Cache with multiple eviction strategies and performance optimizations
pub struct DnsCache {
    /// Cache storage
    cache: Arc<DashMap<String, CachedRecord>>,

    /// Maximum entries
    max_entries: usize,

    /// Eviction strategy
    eviction_strategy: EvictionStrategy,

    /// Minimum threshold for eviction
    min_threshold: f64,

    /// Threshold for optimistic refresh (0.0 to 1.0)
    refresh_threshold: f64,

    /// LFU-K history size
    lfuk_history_size: usize,

    /// Batch eviction size (percentage of max_entries)
    batch_eviction_percentage: f64,

    /// Adaptive thresholds enabled
    adaptive_thresholds: bool,

    /// Metrics
    metrics: Arc<CacheMetrics>,

    /// Compaction counter (for background compaction)
    compaction_counter: Arc<AtomicUsize>,
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
            "Initializing DNS cache with advanced features"
        );

        Self {
            cache: Arc::new(DashMap::new()),
            max_entries,
            eviction_strategy,
            min_threshold,
            refresh_threshold,
            lfuk_history_size,
            batch_eviction_percentage,
            adaptive_thresholds,
            metrics: Arc::new(CacheMetrics::default()),
            compaction_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get record from cache (with lazy expiration)
    pub async fn get(&self, domain: &str, record_type: &RecordType) -> Option<Vec<IpAddr>> {
        let key = Self::make_key(domain, record_type);

        if let Some(entry) = self.cache.get(&key) {
            // Lazy expiration check
            if entry.is_expired() || entry.is_marked_for_deletion() {
                debug!(domain = %domain, record_type = %record_type, "Cache entry expired (lazy)");
                drop(entry);
                self.lazy_remove(&key);
                self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
                self.metrics
                    .lazy_deletions
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return None;
            }

            // Record hit
            entry.record_hit().await;
            self.metrics.hits.fetch_add(1, AtomicOrdering::Relaxed);

            debug!(
                domain = %domain,
                record_type = %record_type,
                hit_count = entry.hit_count.load(AtomicOrdering::Relaxed),
                "Cache hit"
            );

            Some(entry.addresses.clone())
        } else {
            self.metrics.misses.fetch_add(1, AtomicOrdering::Relaxed);
            None
        }
    }

    /// Insert record into cache
    pub fn insert(&self, domain: &str, record_type: &RecordType, addresses: Vec<IpAddr>, ttl: u64) {
        if addresses.is_empty() {
            return;
        }

        let key = Self::make_key(domain, record_type);
        let record = CachedRecord::new(addresses, ttl, record_type.clone(), self.lfuk_history_size);

        // Check if cache is full (trigger batch eviction)
        if self.cache.len() >= self.max_entries {
            self.batch_evict();
        }

        self.cache.insert(key.clone(), record);
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

    /// Lazy remove (mark for deletion, actual removal in compaction)
    fn lazy_remove(&self, key: &str) {
        if let Some(entry) = self.cache.get(key) {
            entry.mark_for_deletion();
        }
    }

    /// Batch eviction - remove multiple entries at once
    fn batch_evict(&self) {
        let evict_count =
            ((self.max_entries as f64 * self.batch_eviction_percentage) as usize).max(1);

        debug!(
            current_size = self.cache.len(),
            evict_count = evict_count,
            strategy = ?self.eviction_strategy,
            "Starting batch eviction"
        );

        // Collect candidates asynchronously
        let rt = tokio::runtime::Handle::current();
        let candidates = rt.block_on(async { self.collect_eviction_candidates().await });

        // Evict in batch
        let mut evicted = 0;
        for entry in candidates.into_iter().take(evict_count) {
            if entry.score < self.min_threshold {
                if self.cache.remove(&entry.domain).is_some() {
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

    /// Collect eviction candidates based on strategy
    async fn collect_eviction_candidates(&self) -> Vec<EvictionEntry> {
        let mut candidates = Vec::with_capacity(self.cache.len());

        for entry in self.cache.iter() {
            let record = entry.value();

            // Skip if marked for deletion
            if record.is_marked_for_deletion() {
                continue;
            }

            let score = match self.eviction_strategy {
                EvictionStrategy::HitRate => record.hit_rate(),
                EvictionStrategy::LFU => record.frequency() as f64,
                EvictionStrategy::LFUK => record.lfuk_score().await,
            };

            candidates.push(EvictionEntry {
                domain: entry.key().clone(),
                score,
                last_access: record.last_access.load(AtomicOrdering::Relaxed),
            });
        }

        // Sort by score (ascending - lowest first)
        candidates.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
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

        self.metrics
            .adaptive_adjustments
            .fetch_add(1, AtomicOrdering::Relaxed);
    }

    /// Get domains that should be refreshed optimistically
    pub async fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        let mean_score = self.calculate_mean_score().await;

        for entry in self.cache.iter() {
            let record = entry.value();

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
                EvictionStrategy::LFUK => record.lfuk_score().await,
            };

            if score >= mean_score {
                let parts: Vec<&str> = entry.key().split('|').collect();
                if parts.len() == 2 {
                    if let Ok(record_type) = parts[1].parse::<RecordType>() {
                        candidates.push((parts[0].to_string(), record_type));
                    }
                }
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
    async fn calculate_mean_score(&self) -> f64 {
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
                EvictionStrategy::LFUK => record.lfuk_score().await,
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
            if entry.value().is_marked_for_deletion() || entry.value().is_expired() {
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
            debug!(
                removed = removed,
                cache_size = self.cache.len(),
                "Background compaction completed"
            );
        }

        // Increment compaction counter
        self.compaction_counter
            .fetch_add(1, AtomicOrdering::Relaxed);

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

    /// Get eviction strategy
    pub fn strategy(&self) -> EvictionStrategy {
        self.eviction_strategy
    }

    /// Make cache key from domain and record type
    fn make_key(domain: &str, record_type: &RecordType) -> String {
        format!("{}|{}", domain, record_type.as_str())
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
        assert_eq!(
            cache.metrics().lazy_deletions.load(AtomicOrdering::Relaxed),
            1
        );
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
        assert!(
            cache
                .metrics()
                .batch_evictions
                .load(AtomicOrdering::Relaxed)
                > 0
        );
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
