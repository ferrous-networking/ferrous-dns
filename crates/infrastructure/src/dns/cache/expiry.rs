use super::schedule::{ScheduledRefresh, TimerKind};
use super::{coarse_clock::coarse_now_secs, storage::DnsCache, CacheKey};
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Removes `key` if it is dead at `now_secs` or marked for deletion, for
    /// the timer that found it so. A record stored over it since is alive and
    /// stays.
    pub(super) fn remove_dead(&self, key: &CacheKey, now_secs: u64) -> bool {
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
    /// timer its insert armed.
    pub fn expire_negative(&self, key: &CacheKey, now_secs: u64) -> bool {
        let removed = self.negative.remove_expired(key, now_secs);
        if removed {
            self.metrics
                .compactions
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        removed
    }

    /// Arms the timer that removes `key` at `dead_at_secs`, the second it
    /// stops being usable. For an entry parked with no renewal pending.
    pub(super) fn arm_expiry(&self, key: &CacheKey, dead_at_secs: u64) {
        if let Some(inbox) = self.timer_inbox() {
            inbox.push(ScheduledRefresh {
                due_at_secs: dead_at_secs,
                key: key.clone(),
                kind: TimerKind::Due,
            });
        }
    }

    /// Arms the next renewal of an entry whose renewal ended without renewing
    /// it and gets no retry of its own: `after_secs` from now, or the second
    /// it dies if that comes first, when the timer removes it instead. An
    /// entry with a timer pending, such as one a renewal or a re-arm armed in
    /// the meantime, keeps it.
    ///
    /// Only this timer retries it, never a hit, so a failing upstream is asked
    /// once per `after_secs` (`cache_compaction_interval`), not once per hit.
    pub(crate) fn rearm_lapsed(&self, key: &CacheKey, after_secs: u64) {
        let Some(entry) = self.cache.get(key) else {
            return;
        };
        let Some(inbox) = self.renewing_inbox(entry.ttl) else {
            return;
        };
        let due_at_secs = coarse_now_secs()
            .saturating_add(after_secs)
            .min(entry.refresh_deadline_secs());
        if !entry.try_rearm_lapsed_refresh(due_at_secs) {
            return;
        }
        drop(entry);
        inbox.push(ScheduledRefresh {
            due_at_secs,
            key: key.clone(),
            kind: TimerKind::Due,
        });
    }
}
