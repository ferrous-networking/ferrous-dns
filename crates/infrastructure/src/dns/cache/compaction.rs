use super::storage::DnsCache;
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

impl DnsCache {
    pub fn compact(&self) -> usize {
        let mut removed = 0;

        self.cache.retain(|_key, record| {
            if record.is_marked_for_deletion() || record.is_expired() {
                removed += 1;
                false
            } else {
                true
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

    pub fn cleanup_expired(&self) -> usize {
        self.compact()
    }

    pub fn compaction_count(&self) -> usize {
        self.compaction_counter.load(AtomicOrdering::Relaxed)
    }
}
