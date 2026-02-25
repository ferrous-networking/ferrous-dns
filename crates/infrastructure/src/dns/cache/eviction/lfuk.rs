use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

pub struct LfukPolicy {
    pub min_lfuk_score: f64,
    pub k_value: f64,
}

impl EvictionPolicy for LfukPolicy {
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        let last_access = record.counters.last_access.load(Ordering::Relaxed);
        let hits = record.counters.hit_count.load(Ordering::Relaxed) as f64;

        if hits == 0.0 {
            return self.min_lfuk_score;
        }

        let age_secs = now_secs.saturating_sub(record.inserted_at_secs).max(1) as f64;
        let idle_secs = now_secs.saturating_sub(last_access) as f64;

        let age_decay = if (self.k_value - 0.5).abs() < f64::EPSILON {
            age_secs.sqrt().max(1.0)
        } else {
            age_secs.powf(self.k_value).max(1.0)
        };

        let score = hits / age_decay * (1.0 / (idle_secs + 1.0));

        if self.min_lfuk_score > 0.0 && score < self.min_lfuk_score {
            score - self.min_lfuk_score
        } else {
            score
        }
    }
}
