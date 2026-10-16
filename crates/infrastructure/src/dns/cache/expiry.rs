use super::{storage::DnsCache, CacheKey};
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Removes `key` if it is dead at `now_secs` or marked for deletion, for
    /// the timer or the claim that found it so. A record stored over it since
    /// is alive and stays.
    pub(crate) fn remove_dead(&self, key: &CacheKey, now_secs: u64) -> bool {
        let removed = self
            .cache
            .remove_if(key, |_, record| {
                !record.is_permanent()
                    && (record.is_marked_for_deletion() || record.is_dead_at_secs(now_secs))
            })
            .is_some();
        if removed {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        removed
    }

    /// Removes the negative entry `key` if it expired by `now_secs`, for the
    /// timer its insert armed. Called by the refresh worker; public so tests
    /// can fire a timer as it does.
    pub fn expire_negative(&self, key: &CacheKey, now_secs: u64) -> bool {
        let removed = self.negative.remove_expired(key, now_secs);
        if removed {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        removed
    }
}
