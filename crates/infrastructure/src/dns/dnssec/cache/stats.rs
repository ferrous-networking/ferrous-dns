use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct CacheStats {
    pub(super) dnskey_hits: AtomicU64,
    pub(super) dnskey_misses: AtomicU64,
    pub(super) ds_hits: AtomicU64,
    pub(super) ds_misses: AtomicU64,
    pub(super) ds_denial_fail_opens: AtomicU64,
}

impl CacheStats {
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

    /// A delegation was served as Insecure because the upstream returned no
    /// authenticated NSEC/NSEC3 proving the DS RRset absent. Expected to be
    /// zero-ish: a non-trivial rate means the configured upstreams strip the
    /// authority section, and the anti-downgrade check is not actually
    /// protecting those lookups.
    pub fn record_ds_denial_fail_open(&self) {
        self.ds_denial_fail_opens.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_ds_denial_fail_opens(&self) -> u64 {
        self.ds_denial_fail_opens.load(Ordering::Relaxed)
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
}

#[derive(Debug, Clone)]
pub struct CacheStatsSnapshot {
    pub dnskey_entries: usize,
    pub ds_entries: usize,
    pub total_dnskey_hits: u64,
    pub total_dnskey_misses: u64,
    pub total_ds_hits: u64,
    pub total_ds_misses: u64,
    pub total_ds_denial_fail_opens: u64,
}

impl CacheStatsSnapshot {
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
