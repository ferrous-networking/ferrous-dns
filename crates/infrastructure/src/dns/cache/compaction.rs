use super::storage::DnsCache;
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

impl DnsCache {
    pub fn compact(&self) -> usize {
        let before = self.cache.len();
        self.cache
            .retain(|_, record| !record.is_marked_for_deletion());
        let removed = before.saturating_sub(self.cache.len());

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

    pub fn compaction_count(&self) -> usize {
        self.compaction_counter.load(AtomicOrdering::Relaxed)
    }
}
