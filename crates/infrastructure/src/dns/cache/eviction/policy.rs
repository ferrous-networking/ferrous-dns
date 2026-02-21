use crate::dns::cache::record::CachedRecord;

pub trait EvictionPolicy: Send + Sync {
    fn compute_score(&self, record: &CachedRecord, now_secs: u64) -> f64;
}
