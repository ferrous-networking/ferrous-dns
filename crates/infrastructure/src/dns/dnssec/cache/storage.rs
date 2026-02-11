use super::super::types::{DnskeyRecord, DsRecord};
use super::super::validation::ValidationResult;
use super::entries::{DnskeyEntry, DsEntry, ValidationEntry};
use super::stats::{CacheStats, CacheStatsSnapshot};
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use std::sync::Arc;
use tracing::{debug, trace};

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
    pub fn cache_validation(
        &self,
        domain: &str,
        record_type: RecordType,
        result: ValidationResult,
        ttl_seconds: u32,
    ) {
        let key = (Arc::from(domain), record_type);
        let entry = ValidationEntry::new(result, ttl_seconds);

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
            if !entry.is_expired() {
                // Cache hit
                self.stats.record_validation_hit(domain);

                trace!(
                    domain = %domain,
                    record_type = ?record_type,
                    "Validation cache hit"
                );

                return Some(*entry.result());
            } else {
                // Expired - remove it
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
        self.stats.record_validation_miss(domain);
        None
    }

    /// Cache DNSKEY records
    pub fn cache_dnskey(&self, domain: &str, keys: Vec<DnskeyRecord>, ttl_seconds: u32) {
        let key = Arc::from(domain);
        let entry = DnskeyEntry::new(keys, ttl_seconds);

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
            if !entry.is_expired() {
                // Cache hit
                self.stats.record_dnskey_hit(domain);

                trace!(
                    domain = %domain,
                    "DNSKEY cache hit"
                );

                return Some(entry.keys().to_vec());
            } else {
                // Expired
                drop(entry);
                self.dnskeys.remove(&key);

                debug!(
                    domain = %domain,
                    "DNSKEY cache expired"
                );
            }
        }

        // Cache miss
        self.stats.record_dnskey_miss(domain);
        None
    }

    /// Cache DS records
    pub fn cache_ds(&self, domain: &str, records: Vec<DsRecord>, ttl_seconds: u32) {
        let key = Arc::from(domain);
        let entry = DsEntry::new(records, ttl_seconds);

        self.ds_records.insert(key, entry);

        trace!(
            domain = %domain,
            ttl = ttl_seconds,
            "Cached DS records"
        );
    }

    /// Get cached DS records
    pub fn get_ds(&self, domain: &str) -> Option<Vec<DsRecord>> {
        let key = Arc::from(domain);

        if let Some(entry) = self.ds_records.get(&key) {
            if !entry.is_expired() {
                // Cache hit
                self.stats.record_ds_hit(domain);

                trace!(
                    domain = %domain,
                    "DS cache hit"
                );

                return Some(entry.records().to_vec());
            } else {
                // Expired
                drop(entry);
                self.ds_records.remove(&key);

                debug!(
                    domain = %domain,
                    "DS cache expired"
                );
            }
        }

        // Cache miss
        self.stats.record_ds_miss(domain);
        None
    }

    /// Get cache statistics snapshot
    pub fn stats(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            validation_entries: self.validations.len(),
            dnskey_entries: self.dnskeys.len(),
            ds_entries: self.ds_records.len(),
            total_validation_hits: self.stats.total_validation_hits(),
            total_validation_misses: self.stats.total_validation_misses(),
            total_dnskey_hits: self.stats.total_dnskey_hits(),
            total_dnskey_misses: self.stats.total_dnskey_misses(),
            total_ds_hits: self.stats.total_ds_hits(),
            total_ds_misses: self.stats.total_ds_misses(),
        }
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.validations.clear();
        self.dnskeys.clear();
        self.ds_records.clear();
        debug!("DNSSEC cache cleared");
    }
}

impl Default for DnssecCache {
    fn default() -> Self {
        Self::new()
    }
}
