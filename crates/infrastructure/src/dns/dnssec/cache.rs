use super::chain::ValidationResult;
use super::types::{DnskeyRecord, DsRecord};
use compact_str::CompactString;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Cached validation entry with TTL
#[derive(Debug, Clone)]
struct ValidationEntry {
    result: ValidationResult,
    expires_at: Instant,
}

/// Cached DNSKEY entry with TTL
#[derive(Debug, Clone)]
struct DnskeyEntry {
    keys: Vec<DnskeyRecord>,
    expires_at: Instant,
}

/// Cached DS entry with TTL
#[derive(Debug, Clone)]
struct DsEntry {
    records: Vec<DsRecord>,
    expires_at: Instant,
}

/// High-performance DNSSEC cache
///
/// Uses DashMap for lock-free concurrent access with TTL-based expiration.
///
/// ## Features
///
/// - Lock-free reads and writes
/// - Automatic TTL expiration
/// - Zero-copy domain names (Arc<str>)
/// - Concurrent access from multiple threads
///
/// ## Example
///
/// ```rust,no_run
/// let cache = DnssecCache::new();
///
/// // Cache result (TTL 300 seconds)
/// cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 300);
///
/// // Get result
/// if let Some(result) = cache.get_validation("google.com", RecordType::A) {
///     println!("Cache hit!");
/// }
/// ```
pub struct DnssecCache {
    /// Validation results cache: (domain, record_type) -> ValidationResult
    validations: DashMap<(Arc<str>, RecordType), ValidationEntry>,

    /// DNSKEY cache: domain -> Vec<DnskeyRecord>
    dnskeys: DashMap<Arc<str>, DnskeyEntry>,

    /// DS cache: domain -> Vec<DsRecord>
    ds_records: DashMap<Arc<str>, DsEntry>,

    /// Statistics
    stats: Arc<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    validation_hits: dashmap::DashMap<CompactString, u64>,
    validation_misses: dashmap::DashMap<CompactString, u64>,
    dnskey_hits: dashmap::DashMap<CompactString, u64>,
    dnskey_misses: dashmap::DashMap<CompactString, u64>,
    ds_hits: dashmap::DashMap<CompactString, u64>,
    ds_misses: dashmap::DashMap<CompactString, u64>,
}

impl DnssecCache {
    /// Create a new DNSSEC cache
    pub fn new() -> Self {
        Self {
            validations: DashMap::new(),
            dnskeys: DashMap::new(),
            ds_records: DashMap::new(),
            stats: Arc::new(CacheStats::default()),
        }
    }

    /// Cache a validation result
    ///
    /// ## Arguments
    ///
    /// - `domain`: Domain name (e.g., "google.com")
    /// - `record_type`: Record type (A, AAAA, etc.)
    /// - `result`: Validation result
    /// - `ttl_seconds`: Time to live in seconds
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 300);
    /// ```
    pub fn cache_validation(
        &self,
        domain: &str,
        record_type: RecordType,
        result: ValidationResult,
        ttl_seconds: u64,
    ) {
        let key = (Arc::from(domain), record_type);
        let expires_at = Instant::now() + Duration::from_secs(ttl_seconds);

        let entry = ValidationEntry { result, expires_at };

        self.validations.insert(key, entry);

        trace!(
            domain = %domain,
            record_type = ?record_type,
            ttl = ttl_seconds,
            "Cached validation result"
        );
    }

    /// Get cached validation result
    ///
    /// Returns `None` if not cached or expired.
    pub fn get_validation(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Option<ValidationResult> {
        let key = (Arc::from(domain), record_type);

        if let Some(entry) = self.validations.get(&key) {
            if entry.expires_at > Instant::now() {
                // Cache hit
                self.stats
                    .validation_hits
                    .entry(CompactString::from(domain))
                    .and_modify(|c| *c += 1)
                    .or_insert(1);

                trace!(
                    domain = %domain,
                    record_type = ?record_type,
                    "Validation cache hit"
                );

                return Some(entry.result);
            } else {
                // Expired
                drop(entry);
                self.validations.remove(&key);

                debug!(
                    domain = %domain,
                    record_type = ?record_type,
                    "Validation cache expired"
                );
            }
        }

        // Cache miss
        self.stats
            .validation_misses
            .entry(CompactString::from(domain))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        None
    }

    /// Cache DNSKEY records
    pub fn cache_dnskey(&self, domain: &str, keys: Vec<DnskeyRecord>, ttl_seconds: u64) {
        let key = Arc::from(domain);
        let expires_at = Instant::now() + Duration::from_secs(ttl_seconds);

        let entry = DnskeyEntry { keys, expires_at };

        self.dnskeys.insert(key, entry);

        trace!(
            domain = %domain,
            ttl = ttl_seconds,
            "Cached DNSKEY records"
        );
    }

    /// Get cached DNSKEY records
    pub fn get_dnskey(&self, domain: &str) -> Option<Vec<DnskeyRecord>> {
        let key = Arc::from(domain);

        if let Some(entry) = self.dnskeys.get(&key) {
            if entry.expires_at > Instant::now() {
                // Cache hit
                self.stats
                    .dnskey_hits
                    .entry(CompactString::from(domain))
                    .and_modify(|c| *c += 1)
                    .or_insert(1);

                trace!(domain = %domain, "DNSKEY cache hit");

                return Some(entry.keys.clone());
            } else {
                // Expired
                drop(entry);
                self.dnskeys.remove(&key);

                debug!(domain = %domain, "DNSKEY cache expired");
            }
        }

        // Cache miss
        self.stats
            .dnskey_misses
            .entry(CompactString::from(domain))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        None
    }

    /// Cache DS records
    pub fn cache_ds(&self, domain: &str, records: Vec<DsRecord>, ttl_seconds: u64) {
        let key = Arc::from(domain);
        let expires_at = Instant::now() + Duration::from_secs(ttl_seconds);

        let entry = DsEntry {
            records,
            expires_at,
        };

        self.ds_records.insert(key, entry);

        trace!(domain = %domain, ttl = ttl_seconds, "Cached DS records");
    }

    /// Get cached DS records
    pub fn get_ds(&self, domain: &str) -> Option<Vec<DsRecord>> {
        let key = Arc::from(domain);

        if let Some(entry) = self.ds_records.get(&key) {
            if entry.expires_at > Instant::now() {
                // Cache hit
                self.stats
                    .ds_hits
                    .entry(CompactString::from(domain))
                    .and_modify(|c| *c += 1)
                    .or_insert(1);

                trace!(domain = %domain, "DS cache hit");

                return Some(entry.records.clone());
            } else {
                // Expired
                drop(entry);
                self.ds_records.remove(&key);

                debug!(domain = %domain, "DS cache expired");
            }
        }

        // Cache miss
        self.stats
            .ds_misses
            .entry(CompactString::from(domain))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        None
    }

    /// Clear all expired entries
    ///
    /// This is useful for periodic cleanup to free memory.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();

        // Cleanup validations
        self.validations.retain(|_, entry| entry.expires_at > now);

        // Cleanup DNSKEYs
        self.dnskeys.retain(|_, entry| entry.expires_at > now);

        // Cleanup DS records
        self.ds_records.retain(|_, entry| entry.expires_at > now);

        debug!("Cleaned up expired DNSSEC cache entries");
    }

    /// Clear all cache entries
    pub fn clear(&self) {
        self.validations.clear();
        self.dnskeys.clear();
        self.ds_records.clear();

        debug!("Cleared all DNSSEC cache entries");
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            validation_entries: self.validations.len(),
            dnskey_entries: self.dnskeys.len(),
            ds_entries: self.ds_records.len(),
            total_validation_hits: self.stats.validation_hits.iter().map(|r| *r.value()).sum(),
            total_validation_misses: self
                .stats
                .validation_misses
                .iter()
                .map(|r| *r.value())
                .sum(),
            total_dnskey_hits: self.stats.dnskey_hits.iter().map(|r| *r.value()).sum(),
            total_dnskey_misses: self.stats.dnskey_misses.iter().map(|r| *r.value()).sum(),
            total_ds_hits: self.stats.ds_hits.iter().map(|r| *r.value()).sum(),
            total_ds_misses: self.stats.ds_misses.iter().map(|r| *r.value()).sum(),
        }
    }

    /// Calculate cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let stats = self.stats();
        let total_hits =
            stats.total_validation_hits + stats.total_dnskey_hits + stats.total_ds_hits;
        let total_requests = total_hits
            + stats.total_validation_misses
            + stats.total_dnskey_misses
            + stats.total_ds_misses;

        if total_requests == 0 {
            return 0.0;
        }

        (total_hits as f64 / total_requests as f64) * 100.0
    }
}

impl Default for DnssecCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of cache statistics
#[derive(Debug, Clone)]
pub struct CacheStatsSnapshot {
    pub validation_entries: usize,
    pub dnskey_entries: usize,
    pub ds_entries: usize,
    pub total_validation_hits: u64,
    pub total_validation_misses: u64,
    pub total_dnskey_hits: u64,
    pub total_dnskey_misses: u64,
    pub total_ds_hits: u64,
    pub total_ds_misses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_and_get_validation() {
        let cache = DnssecCache::new();

        // Cache result
        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 10);

        // Should hit
        let result = cache.get_validation("google.com", RecordType::A);
        assert_eq!(result, Some(ValidationResult::Secure));

        // Different domain should miss
        let result = cache.get_validation("example.com", RecordType::A);
        assert_eq!(result, None);

        // Different record type should miss
        let result = cache.get_validation("google.com", RecordType::AAAA);
        assert_eq!(result, None);
    }

    #[test]
    fn test_validation_expiration() {
        let cache = DnssecCache::new();

        // Cache with 0 TTL (immediately expires)
        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 0);

        // Should expire immediately
        std::thread::sleep(Duration::from_millis(10));
        let result = cache.get_validation("google.com", RecordType::A);
        assert_eq!(result, None);
    }

    #[test]
    fn test_cache_dnskey() {
        let cache = DnssecCache::new();

        let dnskey = DnskeyRecord {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
        };

        cache.cache_dnskey("google.com", vec![dnskey.clone()], 10);

        // Should hit
        let keys = cache.get_dnskey("google.com");
        assert!(keys.is_some());
        assert_eq!(keys.unwrap().len(), 1);

        // Different domain should miss
        let keys = cache.get_dnskey("example.com");
        assert!(keys.is_none());
    }

    #[test]
    fn test_cache_ds() {
        let cache = DnssecCache::new();

        let ds = DsRecord {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        };

        cache.cache_ds("google.com", vec![ds.clone()], 10);

        // Should hit
        let records = cache.get_ds("google.com");
        assert!(records.is_some());
        assert_eq!(records.unwrap().len(), 1);

        // Different domain should miss
        let records = cache.get_ds("example.com");
        assert!(records.is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = DnssecCache::new();

        // Add entries with short TTL
        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 0);
        cache.cache_validation("example.com", RecordType::A, ValidationResult::Secure, 10);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup
        cache.cleanup_expired();

        // Short TTL should be gone
        assert_eq!(cache.get_validation("google.com", RecordType::A), None);

        // Long TTL should still exist
        assert_eq!(
            cache.get_validation("example.com", RecordType::A),
            Some(ValidationResult::Secure)
        );
    }

    #[test]
    fn test_clear() {
        let cache = DnssecCache::new();

        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 10);
        cache.cache_dnskey("google.com", vec![], 10);
        cache.cache_ds("google.com", vec![], 10);

        cache.clear();

        assert_eq!(cache.get_validation("google.com", RecordType::A), None);
        assert_eq!(cache.get_dnskey("google.com"), None);
        assert_eq!(cache.get_ds("google.com"), None);
    }

    #[test]
    fn test_stats() {
        let cache = DnssecCache::new();

        // Cache and access
        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 10);
        let _ = cache.get_validation("google.com", RecordType::A); // Hit
        let _ = cache.get_validation("example.com", RecordType::A); // Miss

        let stats = cache.stats();
        assert_eq!(stats.validation_entries, 1);
        assert_eq!(stats.total_validation_hits, 1);
        assert_eq!(stats.total_validation_misses, 1);
    }

    #[test]
    fn test_hit_rate() {
        let cache = DnssecCache::new();

        // No requests yet
        assert_eq!(cache.hit_rate(), 0.0);

        // 1 hit, 1 miss = 50%
        cache.cache_validation("google.com", RecordType::A, ValidationResult::Secure, 10);
        let _ = cache.get_validation("google.com", RecordType::A); // Hit
        let _ = cache.get_validation("example.com", RecordType::A); // Miss

        let hit_rate = cache.hit_rate();
        assert!((hit_rate - 50.0).abs() < 0.1);
    }
}
