use super::storage::DnsCache;
use ferrous_dns_domain::RecordType;

/// Extension methods for DnsCache refresh functionality
impl DnsCache {
    /// Get list of cache entries that should be refreshed proactively
    ///
    /// Returns candidates that:
    /// - Are not expired
    /// - Are not marked for deletion
    /// - Are not negative responses (NXDOMAIN, etc)
    /// - Should be refreshed based on refresh_threshold
    /// - Have score >= mean score (prioritize important entries)
    /// - Are not problematic record types (HTTPS often fails)
    pub fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        let mean_score = self.calculate_mean_score();

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_expired() || record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            if self.compute_score(record) >= mean_score {
                candidates.push((key.domain.to_string(), key.record_type));
            }
        }

        candidates
    }

    /// Reset the refreshing flag for a domain/record type
    ///
    /// Called after a refresh operation completes (successfully or not)
    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;
        use std::sync::atomic::Ordering as AtomicOrdering;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }

    /// Calculate mean score across all valid cache entries
    ///
    /// Used to prioritize which entries to refresh
    fn calculate_mean_score(&self) -> f64 {
        if self.cache.is_empty() {
            return self.get_threshold();
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
            self.get_threshold()
        }
    }
}
