use super::coarse_clock::coarse_now_secs;
use super::storage::DnsCache;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::Ordering as AtomicOrdering;

/// Knobs the maintenance cycle hands to a candidate scan.
///
/// They live here rather than on `DnsCache` because they describe the refresh
/// policy, not the store: `min_lead_secs` is derived from the cycle interval,
/// which only the maintenance layer knows.
#[derive(Debug, Clone, Copy)]
pub struct RefreshScanOptions {
    /// How much life must remain before an entry is taken regardless of the
    /// proportional threshold. Set to twice the cycle interval, which is the
    /// worst-case wait between crossing the threshold and being drained.
    pub min_lead_secs: u64,
    /// Hits per minute, since the last renewal, below which an entry counts as
    /// cold. Only used to decide who is dropped first when a cycle's backlog
    /// does not fit.
    pub min_hit_rate: f64,
    /// Lifetime hits below which an entry counts as cold. Keeps entries that
    /// were only just inserted from displacing an established working set.
    pub min_frequency: u64,
}

impl DnsCache {
    /// Claims every entry due for renewal, ordered by how urgently it needs it.
    ///
    /// Ordering is `(cold, deadline)`. Deadline first would be the obvious
    /// choice, but the list only gets truncated when a cycle's backlog does not
    /// fit, and in that situation the question is not which entry dies soonest
    /// but which death costs most: a hot entry that dies costs one slow query
    /// per client that wanted it, a cold one costs a single query. Within each
    /// class the deadline decides, so nothing hot is ever starved by something
    /// hotter but less urgent.
    pub fn get_refresh_candidates(
        &self,
        opts: &RefreshScanOptions,
    ) -> Vec<(CompactString, RecordType)> {
        let mut candidates: Vec<(bool, u64, CompactString, RecordType)> = Vec::with_capacity(16);
        let now = coarse_now_secs();
        let sample_period = self.refresh_sample_period;
        let mut idx: u64 = 0;

        for entry in self.cache.iter() {
            idx += 1;
            if sample_period > 1 && !idx.is_multiple_of(sample_period) {
                continue;
            }
            let record = entry.value();

            if record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            // `refresh_record` refuses permanent entries, so queueing one burns
            // a drain slot on a guaranteed no-op.
            if record.is_permanent() {
                continue;
            }

            let key = entry.key();
            let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
            let age_since_access = now.saturating_sub(last_access);
            let within_window = age_since_access <= self.access_window_secs;

            if !within_window {
                continue;
            }

            let expired = record.is_expired_at_secs(now);

            if expired && !record.is_stale_usable_at_secs(now) {
                continue;
            }

            if !expired && !record.should_refresh(self.refresh_threshold, now, opts.min_lead_secs) {
                continue;
            }

            if !record.try_set_refresh_queued() {
                continue;
            }

            let hits = record.counters.hit_count.load(AtomicOrdering::Relaxed);
            let is_cold = record.hits_per_minute_since_refresh(now) < opts.min_hit_rate
                || hits < opts.min_frequency;

            candidates.push((
                is_cold,
                record.refresh_deadline_secs(),
                key.domain.clone(),
                key.record_type,
            ));
        }

        candidates.sort_unstable_by_key(|(is_cold, deadline, _, _)| (*is_cold, *deadline));

        candidates
            .into_iter()
            .map(|(_, _, domain, record_type)| (domain, record_type))
            .collect()
    }

    /// Releases the queue claim on a candidate the cycle could not hand over.
    ///
    /// Only the queue flag: an in-flight resolution, if one somehow started in
    /// between, is none of this path's business.
    pub fn reset_refresh_queued(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refresh_queued();
        }
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refreshing();
        }
    }
}
