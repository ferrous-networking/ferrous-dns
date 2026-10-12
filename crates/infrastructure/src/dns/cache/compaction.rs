use super::schedule::ScheduledRefresh;
use super::{coarse_clock::coarse_now_secs, storage::DnsCache, CacheKey, CachedRecord};
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

impl DnsCache {
    /// Removes dead entries and re-arms live ones that missed their renewal.
    ///
    /// The second job rides on this pass because it already visits every
    /// entry. An entry in use whose renewal came due and failed, and was not
    /// retried, has no timer left: it gets one here, so a failing upstream is
    /// retried once per compaction interval instead of never.
    pub fn compact(&self) -> usize {
        let before = self.cache.len();
        let now = coarse_now_secs();
        let rearm = self.schedules_refreshes();
        let mut overdue: Vec<CacheKey> = Vec::new();
        self.cache.retain(|key, record| {
            let keep = !record.is_marked_for_deletion()
                && (!record.is_expired_at_secs(now) || record.is_stale_usable_at_secs(now));
            if keep && rearm && self.missed_its_renewal(record, now) {
                overdue.push(key.clone());
            }
            keep
        });
        let removed = before.saturating_sub(self.cache.len()) + self.negative.purge_expired(now);

        for key in overdue {
            if let Some(entry) = self.cache.get(&key) {
                entry.try_arm_refresh();
            }
            self.send_or_disarm(ScheduledRefresh {
                due_at_secs: now,
                key,
                retry: false,
            });
        }

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

        removed
    }

    /// In use, past the second it fell due, and not being renewed.
    fn missed_its_renewal(&self, record: &CachedRecord, now_secs: u64) -> bool {
        if record.is_permanent() || record.is_refreshing() || record.ttl == 0 {
            return false;
        }
        let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
        now_secs.saturating_sub(last_access) <= self.access_window_secs
            && record.refresh_due_at_secs(self.refresh_threshold) <= now_secs
    }
}
