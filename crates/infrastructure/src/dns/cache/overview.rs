use super::coarse_clock::coarse_now_secs;
use super::storage::DnsCache;
use ferrous_dns_application::ports::{CacheOverview, CacheTopRefreshed};
use ferrous_dns_domain::RecordType;
use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Keeps the `top` most renewed entries and counts the entries whose TTL
    /// ends within `expiring_within_secs`. Skips what the listing skips, and
    /// permanent entries, which neither expire nor renew. Only an entry that
    /// enters the top is copied.
    pub fn overview(&self, top: usize, expiring_within_secs: u64) -> CacheOverview {
        let now = coarse_now_secs();
        let mut top_refreshed: Vec<CacheTopRefreshed> = Vec::with_capacity(top + 1);
        let mut expiring_soon = 0;

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_marked_for_deletion()
                || record.data.is_negative()
                || record.is_permanent()
                || record.is_dead_at_secs(now)
            {
                continue;
            }

            if !record.is_expired_at_secs(now)
                && record.expires_at_secs - now <= expiring_within_secs
            {
                expiring_soon += 1;
            }

            let refreshes = record.counters.refresh_count.load(AtomicOrdering::Relaxed);
            if refreshes == 0 {
                continue;
            }
            let domain = entry.key().domain.as_str();
            let rank = top_refreshed
                .iter()
                .position(|other| outranks(refreshes, domain, record.record_type, other))
                .unwrap_or(top_refreshed.len());
            if rank < top {
                top_refreshed.insert(
                    rank,
                    CacheTopRefreshed {
                        domain: domain.to_string(),
                        record_type: record.record_type,
                        refreshes,
                    },
                );
                top_refreshed.truncate(top);
            }
        }

        CacheOverview {
            top_refreshed,
            expiring_soon,
        }
    }
}

/// More renewals first, then the listing's tie-break: domain, then type.
fn outranks(
    refreshes: u64,
    domain: &str,
    record_type: RecordType,
    other: &CacheTopRefreshed,
) -> bool {
    refreshes
        .cmp(&other.refreshes)
        .then_with(|| other.domain.as_str().cmp(domain))
        .then_with(|| other.record_type.to_u16().cmp(&record_type.to_u16()))
        == Ordering::Greater
}
