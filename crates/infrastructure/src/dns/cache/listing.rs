use super::coarse_clock::coarse_now_secs;
use super::key::CacheKey;
use super::record::CachedRecord;
use super::storage::DnsCache;
use ferrous_dns_application::ports::{
    CacheEntryOrder, CacheEntryPage, CacheEntryQuery, CacheEntrySnapshot, CacheEntrySort,
};
use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    /// Builds a filtered, ordered and paginated snapshot of the positive
    /// cache for the admin UI. Entries still inside the stale grace period
    /// are listed (the resolver still serves them) and flagged as stale;
    /// entries marked for deletion, negative responses and fully expired
    /// records are skipped.
    pub fn list_entries(&self, query: &CacheEntryQuery) -> CacheEntryPage {
        let now = coarse_now_secs();
        let domain_filter = query.domain.as_deref().map(str::to_ascii_lowercase);

        let mut matched: Vec<CacheEntrySnapshot> = Vec::new();

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            if record.is_expired_at_secs(now) && !record.is_stale_usable_at_secs(now) {
                continue;
            }

            let key = entry.key();

            if let Some(needle) = domain_filter.as_deref() {
                if !key.domain.as_str().contains(needle) {
                    continue;
                }
            }

            if let Some(record_type) = query.record_type {
                if key.record_type != record_type {
                    continue;
                }
            }

            matched.push(snapshot_from(key, record, now));
        }

        let total = matched.len();
        sort_entries(&mut matched, query.sort, query.order);

        let entries = matched
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        CacheEntryPage {
            entries,
            total,
            records_total: self.len(),
        }
    }
}

fn snapshot_from(key: &CacheKey, record: &CachedRecord, now_secs: u64) -> CacheEntrySnapshot {
    let is_permanent = record.is_permanent();
    let remaining_ttl = if is_permanent {
        None
    } else {
        let remaining = record.expires_at_secs.saturating_sub(now_secs);
        Some(remaining.min(u32::MAX as u64) as u32)
    };

    CacheEntrySnapshot {
        domain: key.domain.to_string(),
        record_type: record.record_type,
        group_id: (key.view != 0).then(|| i64::from(key.view)),
        answers: record
            .data
            .as_ip_addresses()
            .map(|addresses| addresses.as_ref().clone())
            .unwrap_or_default(),
        canonical_name: record.data.as_canonical_name().map(|name| name.to_string()),
        dnssec_status: record.dnssec_status.to_domain(),
        ttl: record.ttl,
        remaining_ttl,
        cached_at_secs: record.inserted_at_secs,
        expires_at_secs: record.expires_at_secs,
        hits: record.counters.hit_count.load(AtomicOrdering::Relaxed),
        refreshes: record.counters.refresh_count.load(AtomicOrdering::Relaxed),
        last_access_secs: record.counters.last_access.load(AtomicOrdering::Relaxed),
        is_permanent,
        is_stale: record.is_stale_usable_at_secs(now_secs),
    }
}

fn sort_entries(entries: &mut [CacheEntrySnapshot], sort: CacheEntrySort, order: CacheEntryOrder) {
    entries.sort_by(|a, b| {
        let primary = match sort {
            CacheEntrySort::Hits => a.hits.cmp(&b.hits),
            CacheEntrySort::Refreshes => a.refreshes.cmp(&b.refreshes),
            CacheEntrySort::CachedAt => a.cached_at_secs.cmp(&b.cached_at_secs),
            CacheEntrySort::ExpiresAt => a.expires_at_secs.cmp(&b.expires_at_secs),
            CacheEntrySort::Domain => a.domain.cmp(&b.domain),
            CacheEntrySort::Type => a.record_type.to_u16().cmp(&b.record_type.to_u16()),
        };

        let primary = match order {
            CacheEntryOrder::Asc => primary,
            CacheEntryOrder::Desc => primary.reverse(),
        };

        primary.then_with(|| tie_break(a, b))
    });
}

/// The `DashMap` has no stable iteration order, so equal sort keys are broken
/// by `(domain, record type, group)` — always ascending, so paging is
/// reproducible in both directions.
fn tie_break(a: &CacheEntrySnapshot, b: &CacheEntrySnapshot) -> Ordering {
    a.domain
        .cmp(&b.domain)
        .then_with(|| a.record_type.to_u16().cmp(&b.record_type.to_u16()))
        .then_with(|| a.group_id.cmp(&b.group_id))
}
