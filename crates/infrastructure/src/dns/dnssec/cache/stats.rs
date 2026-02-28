use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct CacheStats {
    pub(super) validation_hits: AtomicU64,
    pub(super) validation_misses: AtomicU64,
    pub(super) dnskey_hits: AtomicU64,
    pub(super) dnskey_misses: AtomicU64,
    pub(super) ds_hits: AtomicU64,
    pub(super) ds_misses: AtomicU64,
}

impl CacheStats {
    pub fn record_validation_hit(&self, _domain: &str) {
        self.validation_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_validation_miss(&self, _domain: &str) {
        self.validation_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnskey_hit(&self, _domain: &str) {
        self.dnskey_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnskey_miss(&self, _domain: &str) {
        self.dnskey_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ds_hit(&self, _domain: &str) {
        self.ds_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ds_miss(&self, _domain: &str) {
        self.ds_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_validation_hits(&self) -> u64 {
        self.validation_hits.load(Ordering::Relaxed)
    }

    pub fn total_validation_misses(&self) -> u64 {
        self.validation_misses.load(Ordering::Relaxed)
    }

    pub fn total_dnskey_hits(&self) -> u64 {
        self.dnskey_hits.load(Ordering::Relaxed)
    }

    pub fn total_dnskey_misses(&self) -> u64 {
        self.dnskey_misses.load(Ordering::Relaxed)
    }

    pub fn total_ds_hits(&self) -> u64 {
        self.ds_hits.load(Ordering::Relaxed)
    }

    pub fn total_ds_misses(&self) -> u64 {
        self.ds_misses.load(Ordering::Relaxed)
    }

    pub fn validation_hit_rate(&self) -> f64 {
        let hits = self.total_validation_hits();
        let total = hits + self.total_validation_misses();

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStatsSnapshot {
    pub validation_entries: usize,
    pub dnskey_entries: usize,
    pub ds_entries: usize,
    pub total_validation_hits: u64,
    pub total_validation_misses: u64,
    pub total_dnskey_hits: u64,
    pub total_dnskey_misses: u64,
    pub total_ds_hits: u64,
    pub total_ds_misses: u64,
}

impl CacheStatsSnapshot {
    pub fn validation_hit_rate(&self) -> f64 {
        let total = self.total_validation_hits + self.total_validation_misses;
        if total == 0 {
            0.0
        } else {
            self.total_validation_hits as f64 / total as f64
        }
    }

    pub fn dnskey_hit_rate(&self) -> f64 {
        let total = self.total_dnskey_hits + self.total_dnskey_misses;
        if total == 0 {
            0.0
        } else {
            self.total_dnskey_hits as f64 / total as f64
        }
    }

    pub fn ds_hit_rate(&self) -> f64 {
        let total = self.total_ds_hits + self.total_ds_misses;
        if total == 0 {
            0.0
        } else {
            self.total_ds_hits as f64 / total as f64
        }
    }
}
