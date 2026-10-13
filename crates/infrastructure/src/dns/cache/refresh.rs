use super::key::CacheKey;
use super::record::CachedRecord;
use super::schedule::{ScheduledRefresh, REFRESH_LEAD_SECS};
use super::storage::DnsCache;
use ferrous_dns_domain::RecordType;
use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;

/// Below these an entry counts as cold, and its renewal waits behind hot
/// ones when more are due than the worker runs at once.
///
/// They only rank: every due entry is renewed in the end. Under pressure the
/// question is not which entry dies soonest but which death costs most: a hot
/// entry that dies costs one slow query per client that wanted it, a cold one
/// costs a single query.
#[derive(Debug, Clone, Copy)]
pub struct ColdThresholds {
    /// Hits per minute, since the last renewal.
    pub min_hit_rate: f64,
    /// Lifetime hits. Keeps entries that were only just inserted from
    /// displacing an established working set.
    pub min_frequency: u64,
}

/// A renewal the worker claimed and has yet to start.
#[derive(Debug, Clone)]
pub struct DueRefresh {
    pub key: CacheKey,
    /// Whether this is already the one more attempt after a renewal that did
    /// not renew the entry.
    pub retry: bool,
    is_cold: bool,
    /// The instant past which the entry stops being usable at all.
    deadline_secs: u64,
}

impl DueRefresh {
    fn rank(&self) -> (bool, u64) {
        (self.is_cold, self.deadline_secs)
    }
}

/// Hot before cold, then the earliest deadline, so `BinaryHeap` (a max-heap)
/// pops the most urgent renewal first. Equal means equally urgent, which is
/// all the heap asks; it says nothing about the key.
impl Ord for DueRefresh {
    fn cmp(&self, other: &Self) -> Ordering {
        other.rank().cmp(&self.rank())
    }
}

impl PartialOrd for DueRefresh {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DueRefresh {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for DueRefresh {}

impl DnsCache {
    /// Whether renewing `record` is worth an upstream query: someone asked
    /// for it within `cache_access_window_secs`. A TTL shorter than
    /// `REFRESH_LEAD_SECS` renews more than once a minute, so it must also
    /// have been asked for since its last renewal; otherwise one hit would
    /// keep a 5 s entry renewing every few seconds for the whole window.
    pub(super) fn is_worth_renewing(&self, record: &CachedRecord, now_secs: u64) -> bool {
        let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
        if now_secs.saturating_sub(last_access) > self.access_window_secs {
            return false;
        }
        u64::from(record.ttl) >= REFRESH_LEAD_SECS || last_access >= record.inserted_at_secs
    }

    /// Turns a timer that fired into a claimed renewal.
    ///
    /// A timer that is not the entry's pending one is stale and spends
    /// nothing: a renewal or a re-arm since replaced it. Otherwise the timer
    /// is taken, and the entry is claimed only if it is still usable and
    /// worth renewing (see [`Self::is_worth_renewing`]); one that is not is
    /// parked, and its next hit arms it again.
    pub fn claim_due_refresh(
        &self,
        timer: &ScheduledRefresh,
        now_secs: u64,
        thresholds: &ColdThresholds,
    ) -> Option<DueRefresh> {
        let entry = self.cache.get(&timer.key)?;
        let record = entry.value();
        if record.is_permanent()
            || record.is_marked_for_deletion()
            || !record.try_claim_refresh_timer(timer.due_at_secs)
        {
            return None;
        }
        if record.is_expired_at_secs(now_secs) && !record.is_stale_usable_at_secs(now_secs) {
            record.lapse_claimed_refresh();
            return None;
        }
        if !self.is_worth_renewing(record, now_secs) {
            record.park_claimed_refresh();
            // A hit that read the state before the park armed nothing; the
            // access it recorded is visible now, so it is not missed.
            if !self.is_worth_renewing(record, now_secs) || !record.try_reclaim_parked_refresh() {
                return None;
            }
        }

        let hits = record.counters.hit_count.load(AtomicOrdering::Relaxed);
        Some(DueRefresh {
            key: timer.key.clone(),
            retry: timer.retry,
            is_cold: record.hits_per_minute_since_refresh(now_secs) < thresholds.min_hit_rate
                || hits < thresholds.min_frequency,
            deadline_secs: record.refresh_deadline_secs(),
        })
    }

    /// Starts a claimed renewal that got its permit. `false` means the caller
    /// must not resolve: a renewal since replaced it, a serve-stale repair is
    /// running, or the entry died waiting, which counts as shed because
    /// renewals fell behind what was due.
    ///
    /// The claim held no in-flight bit while it waited, so a client served
    /// stale meanwhile could still queue its own repair.
    pub fn start_claimed_refresh(&self, key: &CacheKey, now_secs: u64) -> bool {
        let Some(entry) = self.cache.get(key) else {
            return false;
        };
        let record = entry.value();
        if record.is_marked_for_deletion() || !record.try_start_claimed_refresh() {
            return false;
        }
        if record.is_expired_at_secs(now_secs) && !record.is_stale_usable_at_secs(now_secs) {
            self.metrics
                .optimistic_refresh_shed
                .fetch_add(1, AtomicOrdering::Relaxed);
            return false;
        }
        record.try_set_refreshing()
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refreshing();
        }
    }
}
