use super::policy::EvictionPolicy;
use crate::dns::cache::record::CachedRecord;
use std::sync::atomic::Ordering;

pub struct LruPolicy;

impl EvictionPolicy for LruPolicy {
    fn compute_score(&self, record: &CachedRecord, _now_secs: u64) -> f64 {
        record.counters.last_access.load(Ordering::Relaxed) as f64
    }
}
