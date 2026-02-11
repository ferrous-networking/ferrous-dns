use super::storage::DnsCache;
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

/// Extension methods for DnsCache compaction and cleanup
impl DnsCache {
    /// Compact the cache by removing expired and deleted entries
    ///
    /// This operation scans the entire cache and physically removes:
    /// - Expired entries (TTL expired)
    /// - Entries marked for deletion (lazy deletion)
    ///
    /// Returns the number of entries removed
    pub fn compact(&self) -> usize {
        let mut removed = 0;

        self.cache.retain(|_key, record| {
            if record.is_marked_for_deletion() || record.is_expired() {
                removed += 1;
                false // Remove
            } else {
                true // Keep
            }
        });

        if removed > 0 {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);

            debug!(
                removed,
                cache_size = self.cache.len(),
                "Cache compaction completed"
            );
        }

        self.compaction_counter
            .fetch_add(1, AtomicOrdering::Relaxed);

        removed
    }

    /// Cleanup expired entries (alias for compact)
    ///
    /// This is the same as compact() but with a more intuitive name
    /// for scheduled cleanup tasks
    pub fn cleanup_expired(&self) -> usize {
        self.compact()
    }

    /// Get the compaction counter
    ///
    /// Returns the number of times compaction has been run (for monitoring)
    pub fn compaction_count(&self) -> usize {
        self.compaction_counter.load(AtomicOrdering::Relaxed)
    }
}
