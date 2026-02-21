use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

pub struct LfuPolicy {
    pub min_frequency: u64,
}

impl EvictionPolicy for LfuPolicy {
    fn compute_score(&self, record: &CachedRecord, _now_secs: u64) -> f64 {
        let hits = record.counters.hit_count.load(Ordering::Relaxed);
        if self.min_frequency > 0 && hits < self.min_frequency {
            -(self.min_frequency as f64 - hits as f64)
        } else {
            hits as f64
        }
    }
}
