use compact_str::CompactString;
use dashmap::DashMap;

#[derive(Debug, Default)]
pub struct CacheStats {
    pub(super) validation_hits: DashMap<CompactString, u64>,
    pub(super) validation_misses: DashMap<CompactString, u64>,
    pub(super) dnskey_hits: DashMap<CompactString, u64>,
    pub(super) dnskey_misses: DashMap<CompactString, u64>,
    pub(super) ds_hits: DashMap<CompactString, u64>,
    pub(super) ds_misses: DashMap<CompactString, u64>,
}

impl CacheStats {
    pub fn record_validation_hit(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.validation_hits
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn record_validation_miss(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.validation_misses
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn record_dnskey_hit(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.dnskey_hits
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn record_dnskey_miss(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.dnskey_misses
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn record_ds_hit(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.ds_hits
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn record_ds_miss(&self, domain: &str) {
        let key = CompactString::new(domain);
        self.ds_misses
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn total_validation_hits(&self) -> u64 {
        self.validation_hits.iter().map(|e| *e.value()).sum()
    }

    pub fn total_validation_misses(&self) -> u64 {
        self.validation_misses.iter().map(|e| *e.value()).sum()
    }

    pub fn total_dnskey_hits(&self) -> u64 {
        self.dnskey_hits.iter().map(|e| *e.value()).sum()
    }

    pub fn total_dnskey_misses(&self) -> u64 {
        self.dnskey_misses.iter().map(|e| *e.value()).sum()
    }

    pub fn total_ds_hits(&self) -> u64 {
        self.ds_hits.iter().map(|e| *e.value()).sum()
    }

    pub fn total_ds_misses(&self) -> u64 {
        self.ds_misses.iter().map(|e| *e.value()).sum()
    }

    pub fn validation_hit_rate(&self) -> f64 {
        let hits = self.total_validation_hits();
        let misses = self.total_validation_misses();
        let total = hits + misses;

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
