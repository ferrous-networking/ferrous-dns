use crate::dns::cache::coarse_clock::coarse_now_secs;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct NegativeQueryTracker {
    query_counts: Arc<DashMap<Arc<str>, QueryCounter>>,
    window_secs: u64,
    frequent_ttl: u32,
    rare_ttl: u32,
    frequency_threshold: u32,
    entry_count: Arc<AtomicU64>,
    frequent_count: Arc<AtomicU64>,
}

struct QueryCounter {
    count: AtomicU64,
    last_reset: u64,
}

impl NegativeQueryTracker {
    pub fn new() -> Self {
        Self::with_config(60, 300, 5, 300)
    }

    pub fn with_config(
        frequent_ttl: u32,
        rare_ttl: u32,
        frequency_threshold: u32,
        window_secs: u64,
    ) -> Self {
        Self {
            query_counts: Arc::new(DashMap::new()),
            window_secs,
            frequent_ttl,
            rare_ttl,
            frequency_threshold,
            entry_count: Arc::new(AtomicU64::new(0)),
            frequent_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_and_get_ttl(&self, domain: &Arc<str>) -> u32 {
        let domain_arc = Arc::clone(domain);
        let now = coarse_now_secs();
        let entry_count = Arc::clone(&self.entry_count);

        let mut entry = self.query_counts.entry(domain_arc).or_insert_with(|| {
            entry_count.fetch_add(1, Ordering::Relaxed);
            QueryCounter {
                count: AtomicU64::new(0),
                last_reset: now,
            }
        });

        if now.saturating_sub(entry.value().last_reset) >= self.window_secs {
            let old_count = entry.value().count.load(Ordering::Relaxed);
            if old_count > self.frequency_threshold as u64 {
                self.frequent_count.fetch_sub(1, Ordering::Relaxed);
            }
            *entry.value_mut() = QueryCounter {
                count: AtomicU64::new(1),
                last_reset: now,
            };
            return self.rare_ttl;
        }

        let count = entry.value().count.fetch_add(1, Ordering::Relaxed) + 1;

        if count == self.frequency_threshold as u64 + 1 {
            self.frequent_count.fetch_add(1, Ordering::Relaxed);
        }

        if count > self.frequency_threshold as u64 {
            self.frequent_ttl
        } else {
            self.rare_ttl
        }
    }

    pub fn stats(&self) -> TrackerStats {
        let total_domains = self.entry_count.load(Ordering::Relaxed) as usize;
        let frequent_domains = self.frequent_count.load(Ordering::Relaxed) as usize;
        TrackerStats {
            total_domains,
            frequent_domains,
            rare_domains: total_domains.saturating_sub(frequent_domains),
            frequent_ttl: self.frequent_ttl,
            rare_ttl: self.rare_ttl,
        }
    }

    pub fn cleanup_old_entries(&self) -> usize {
        let mut removed = 0;
        let now = coarse_now_secs();

        self.query_counts.retain(|_domain, counter| {
            if now.saturating_sub(counter.last_reset) >= self.window_secs {
                let count = counter.count.load(Ordering::Relaxed);
                if count > self.frequency_threshold as u64 {
                    self.frequent_count.fetch_sub(1, Ordering::Relaxed);
                }
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
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
