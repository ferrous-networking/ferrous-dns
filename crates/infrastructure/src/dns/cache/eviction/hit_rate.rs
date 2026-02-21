use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

pub struct HitRatePolicy;

impl EvictionPolicy for HitRatePolicy {
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64 {
        let hits = record.counters.hit_count.load(Ordering::Relaxed);
        let last_access = record.counters.last_access.load(Ordering::Relaxed);
        let age_secs = now_secs.saturating_sub(last_access) as f64;
        let recency = 1.0 / (age_secs + 1.0);
        ((hits as f64) / (hits + 1) as f64) * recency
    }
}
