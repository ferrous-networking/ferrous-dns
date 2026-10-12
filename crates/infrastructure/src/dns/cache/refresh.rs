use super::key::CacheKey;
use super::record::CachedRecord;
use super::schedule::{ScheduledRefresh, REFRESH_LEAD_SECS};
use super::storage::DnsCache;
use ferrous_dns_domain::RecordType;
use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;

/// What sorts due renewals when they outnumber the worker's permits.
///
/// Both only rank: every due entry is renewed in the end. Under pressure the
/// question is not which entry dies soonest but which death costs most: a hot
/// entry that dies costs one slow query per client that wanted it, a cold one
/// costs a single query.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPriority {
    /// Hits per minute, since the last renewal, below which an entry counts
    /// as cold.
    pub min_hit_rate: f64,
    /// Lifetime hits below which an entry counts as cold. Keeps entries that
    /// were only just inserted from displacing an established working set.
    pub min_frequency: u64,
}

/// A renewal the worker claimed and has yet to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueRefresh {
    pub key: CacheKey,
    /// Whether this is already the retry after every upstream answered
    /// SERVFAIL.
    pub retry: bool,
    is_cold: bool,
    /// The instant past which the entry stops being usable at all.
    deadline_secs: u64,
}

/// Hot before cold, then the earliest deadline, so `BinaryHeap` (a max-heap)
/// pops the most urgent renewal first.
impl Ord for DueRefresh {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.is_cold, other.deadline_secs).cmp(&(self.is_cold, self.deadline_secs))
    }
}

impl PartialOrd for DueRefresh {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl DnsCache {
    /// Whether renewing `record` is worth an upstream query: someone asked
    /// for it within `cache_access_window_secs`. A TTL shorter than
    /// `REFRESH_LEAD_SECS` renews more than once a minute, so it must also
    /// have been asked for since its last renewal. Without that, one hit kept
    /// a 5 s entry renewing every few seconds for the whole access window.
    pub(super) fn is_worth_renewing(&self, record: &CachedRecord, now_secs: u64) -> bool {
        let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
        if now_secs.saturating_sub(last_access) > self.access_window_secs {
            return false;
        }
        u64::from(record.ttl) >= REFRESH_LEAD_SECS || last_access >= record.inserted_at_secs
    }

    /// Turns a timer that fired into a claimed renewal, or spends it.
    ///
    /// A timer the record no longer matches, because it was renewed or
    /// replaced since, is left alone: that renewal armed the timer that is
    /// live now. Otherwise the timer is spent whatever happens, and the entry
    /// is only claimed if it is still worth renewing (see
    /// [`Self::is_worth_renewing`]), not past the end of its stale grace, and
    /// not already being renewed by a serve-stale repair.
    pub fn claim_due_refresh(
        &self,
        timer: &ScheduledRefresh,
        now_secs: u64,
        priority: &RefreshPriority,
    ) -> Option<DueRefresh> {
        let entry = self.cache.get(&timer.key)?;
        let record = entry.value();
        if record.is_permanent() || record.is_marked_for_deletion() {
            return None;
        }
        if record.refresh_due_at_secs(self.refresh_threshold) > now_secs {
            return None;
        }

        if !self.is_worth_renewing(record, now_secs) {
            // Left to expire. A hit before then finds the entry disarmed and
            // arms it again.
            record.disarm_refresh();
            return None;
        }
        if record.is_expired_at_secs(now_secs) && !record.is_stale_usable_at_secs(now_secs) {
            return None;
        }
        // A serve-stale repair in flight renews the entry, or, if it fails,
        // leaves it armed for compaction to retry.
        if !record.try_set_refreshing() {
            return None;
        }

        let hits = record.counters.hit_count.load(AtomicOrdering::Relaxed);
        Some(DueRefresh {
            key: timer.key.clone(),
            retry: timer.retry,
            is_cold: record.hits_per_minute_since_refresh(now_secs) < priority.min_hit_rate
                || hits < priority.min_frequency,
            deadline_secs: record.refresh_deadline_secs(),
        })
    }

    /// Whether a claimed renewal is still worth an upstream query after
    /// waiting for a permit. Releases the claim when it is not, and counts an
    /// entry that died waiting as shed: renewals fell behind what was due.
    pub(crate) fn is_still_refreshable(&self, key: &CacheKey, now_secs: u64) -> bool {
        let Some(entry) = self.cache.get(key) else {
            return false;
        };
        let record = entry.value();
        if record.is_expired_at_secs(now_secs) && !record.is_stale_usable_at_secs(now_secs) {
            record.clear_refreshing();
            self.metrics
                .optimistic_refresh_shed
                .fetch_add(1, AtomicOrdering::Relaxed);
            return false;
        }
        true
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refreshing();
        }
    }
}
