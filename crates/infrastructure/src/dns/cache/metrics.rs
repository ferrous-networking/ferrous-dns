use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub insertions: AtomicU64,
    pub evictions: AtomicU64,
    pub optimistic_refreshes: AtomicU64,
    pub lazy_deletions: AtomicU64,
    pub compactions: AtomicU64,
    pub batch_evictions: AtomicU64,
    pub adaptive_adjustments: AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(AtomicOrdering::Relaxed) as f64;
        let total = hits + self.misses.load(AtomicOrdering::Relaxed) as f64;

        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }
}
