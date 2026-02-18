use super::storage::DnsCache;
use ferrous_dns_domain::RecordType;

impl DnsCache {
    
    pub fn get_refresh_candidates(&self) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        let mean_score = self.calculate_mean_score();

        for entry in self.cache.iter() {
            let record = entry.value();

            if record.is_expired() || record.is_marked_for_deletion() {
                continue;
            }

            if record.data.is_negative() {
                continue;
            }

            let key = entry.key();
            if matches!(key.record_type, RecordType::HTTPS) {
                continue;
            }

            if !record.should_refresh(self.refresh_threshold) {
                continue;
            }

            if self.compute_score(record) >= mean_score {
                candidates.push((key.domain.to_string(), key.record_type));
            }
        }

        candidates
    }

    pub fn reset_refreshing(&self, domain: &str, record_type: &RecordType) {
        use super::key::CacheKey;
        use std::sync::atomic::Ordering as AtomicOrdering;

        let key = CacheKey::new(domain, *record_type);
        if let Some(entry) = self.cache.get(&key) {
            entry.refreshing.store(false, AtomicOrdering::Release);
        }
    }

    fn calculate_mean_score(&self) -> f64 {
        if self.cache.is_empty() {
            return self.get_threshold();
        }

        let mut total = 0.0;
        let mut count = 0;

        for entry in self.cache.iter() {
            let record = entry.value();
            if record.is_marked_for_deletion() {
                continue;
            }
            total += self.compute_score(record);
            count += 1;
        }

        if count > 0 {
            total / count as f64
        } else {
            self.get_threshold()
        }
    }
}
