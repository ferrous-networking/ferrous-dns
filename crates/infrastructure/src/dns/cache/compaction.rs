use super::schedule::ScheduledRefresh;
use super::{coarse_clock::coarse_now_secs, storage::DnsCache, CacheKey, CachedRecord};
use std::sync::atomic::Ordering as AtomicOrdering;
use tracing::debug;

impl DnsCache {
    /// Removes dead entries, and arms a timer for live ones that have none.
    ///
    /// The second job rides on this pass because it already visits every
    /// entry. An entry is left with no timer when its renewal failed without
    /// a retry, its timer was shed, or its one more attempt did not renew it
    /// either; arming it here retries a failing upstream once per compaction
    /// pass instead of never. An entry with a timer pending is left alone.
    pub fn compact(&self) -> usize {
        let before = self.cache.len();
        let now = coarse_now_secs();
        let inbox = self.timer_inbox();
        let mut rearmed: Vec<(CacheKey, u64)> = Vec::new();
        self.cache.retain(|key, record| {
            let keep = !record.is_marked_for_deletion()
                && (!record.is_expired_at_secs(now) || record.is_stale_usable_at_secs(now));
            if keep && inbox.is_some() {
                if let Some(due_at_secs) = self.rearm_lapsed(record, now) {
                    rearmed.push((key.clone(), due_at_secs));
                }
            }
            keep
        });
        let removed = before.saturating_sub(self.cache.len()) + self.negative.purge_expired(now);

        if let Some(inbox) = inbox {
            for (key, due_at_secs) in rearmed {
                let timer = ScheduledRefresh {
                    due_at_secs,
                    key,
                    retry: false,
                };
                self.push_or_release(inbox, timer);
            }
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

    /// Arms a lapsed entry in use for the second it falls due, or now if
    /// that passed, and returns it. A lapsed entry nobody uses is parked
    /// instead, so its next hit arms it.
    fn rearm_lapsed(&self, record: &mut CachedRecord, now_secs: u64) -> Option<u64> {
        if !record.is_refresh_lapsed()
            || record.is_permanent()
            || record.is_refreshing()
            || record.ttl == 0
        {
            return None;
        }
        if !self.is_worth_renewing(record, now_secs) {
            record.park_lapsed_refresh();
            return None;
        }
        let due_at_secs = record
            .refresh_due_at_secs(self.refresh_threshold)
            .max(now_secs);
        record.set_refresh_timer(due_at_secs);
        Some(due_at_secs)
    }
}
