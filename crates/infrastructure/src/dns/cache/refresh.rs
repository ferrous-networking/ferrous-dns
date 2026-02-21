use super::coarse_clock::coarse_now_secs;
use super::storage::DnsCache;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::Ordering as AtomicOrdering;

impl DnsCache {
    pub fn get_refresh_candidates(&self) -> Vec<(CompactString, RecordType)> {
        let mut candidates = Vec::with_capacity(16);
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

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            let hit_count = record.counters.hit_count.load(AtomicOrdering::Relaxed);
            let last_access = record.counters.last_access.load(AtomicOrdering::Relaxed);
            let age_since_access = now.saturating_sub(last_access);
            let within_window = hit_count > 0 && age_since_access <= self.access_window_secs;

            if !within_window {
                continue;
            }

            if record.is_expired_at_secs(now) {
                if record.is_stale_usable_at_secs(now) && record.try_set_refreshing() {
                    candidates.push((key.domain.clone(), key.record_type));
                }
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            if record.try_set_refreshing() {
                candidates.push((key.domain.clone(), key.record_type));
            }
        }

        candidates
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.clear_refreshing();
        }
    }
}
