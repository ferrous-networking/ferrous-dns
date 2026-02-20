use crate::dns::cache::coarse_clock::coarse_now_secs;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct NegativeQueryTracker {
    query_counts: Arc<DashMap<Arc<str>, QueryCounter>>,

    frequent_ttl: u32,

    rare_ttl: u32,

    frequency_threshold: u32,
}

struct QueryCounter {
    count: AtomicU64,
    /// Coarse Unix timestamp (seconds) of the last counter reset.
    /// Using `coarse_now_secs()` instead of `Instant` avoids a VDSO/syscall
    /// on every negative-response path (~50 ns → ~3 ns).
    last_reset: u64,
}

impl NegativeQueryTracker {
    pub fn new() -> Self {
        Self {
            query_counts: Arc::new(DashMap::new()),
            frequent_ttl: 60,
            rare_ttl: 300,
            frequency_threshold: 5,
        }
    }

    pub fn with_config(frequent_ttl: u32, rare_ttl: u32, frequency_threshold: u32) -> Self {
        Self {
            query_counts: Arc::new(DashMap::new()),
            frequent_ttl,
            rare_ttl,
            frequency_threshold,
        }
    }

    pub fn record_and_get_ttl(&self, domain: &Arc<str>) -> u32 {
        let domain_arc = Arc::clone(domain);

        let now = coarse_now_secs();

        let mut entry = self
            .query_counts
            .entry(domain_arc)
            .or_insert_with(|| QueryCounter {
                count: AtomicU64::new(0),
                last_reset: now,
            });

        let counter = entry.value();

        if now.saturating_sub(counter.last_reset) >= 300 {
            *entry.value_mut() = QueryCounter {
                count: AtomicU64::new(1),
                last_reset: now,
            };
            return self.rare_ttl;
        }

        let count = counter.count.fetch_add(1, Ordering::Relaxed) + 1;

        if count > self.frequency_threshold as u64 {
            self.frequent_ttl
        } else {
            self.rare_ttl
        }
    }

    pub fn stats(&self) -> TrackerStats {
        let mut frequent_domains = 0;
        let mut rare_domains = 0;

        for entry in self.query_counts.iter() {
            let count = entry.value().count.load(Ordering::Relaxed);
            if count > self.frequency_threshold as u64 {
                frequent_domains += 1;
            } else {
                rare_domains += 1;
            }
        }

        TrackerStats {
            total_domains: self.query_counts.len(),
            frequent_domains,
            rare_domains,
            frequent_ttl: self.frequent_ttl,
            rare_ttl: self.rare_ttl,
        }
    }

    pub fn cleanup_old_entries(&self) -> usize {
        let mut removed = 0;
        let now = coarse_now_secs();

        self.query_counts.retain(|_domain, counter| {
            if now.saturating_sub(counter.last_reset) >= 300 {
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }
}

impl Default for NegativeQueryTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TrackerStats {
    pub total_domains: usize,

    pub frequent_domains: usize,

    pub rare_domains: usize,

    pub frequent_ttl: u32,

    pub rare_ttl: u32,
}
