use super::QueryEvent;
use dashmap::DashMap;
use ferrous_dns_domain::RecordType;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Query event metrics tracker
///
/// Tracks metrics about query events in a thread-safe manner.
/// Uses atomic operations for counters and DashMap for per-domain stats.
#[derive(Clone)]
pub struct QueryMetrics {
    /// Total number of events emitted
    total_events: Arc<AtomicU64>,

    /// Total successful queries
    successful_queries: Arc<AtomicU64>,

    /// Total failed queries
    failed_queries: Arc<AtomicU64>,

    /// Total DNSSEC queries
    dnssec_queries: Arc<AtomicU64>,

    /// Per-domain query counts
    domain_counts: Arc<DashMap<Arc<str>, u64>>,

    /// Per-record-type query counts
    record_type_counts: Arc<DashMap<RecordType, u64>>,

    /// Per-upstream server query counts
    upstream_counts: Arc<DashMap<String, u64>>,

    /// Total response time in microseconds
    total_response_time_us: Arc<AtomicU64>,
}

impl QueryMetrics {
    /// Create a new metrics tracker
    pub fn new() -> Self {
        Self {
            total_events: Arc::new(AtomicU64::new(0)),
            successful_queries: Arc::new(AtomicU64::new(0)),
            failed_queries: Arc::new(AtomicU64::new(0)),
            dnssec_queries: Arc::new(AtomicU64::new(0)),
            domain_counts: Arc::new(DashMap::new()),
            record_type_counts: Arc::new(DashMap::new()),
            upstream_counts: Arc::new(DashMap::new()),
            total_response_time_us: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Track a query event
    pub fn track(&self, event: &QueryEvent) {
        // Update counters
        self.total_events.fetch_add(1, Ordering::Relaxed);

        if event.success {
            self.successful_queries.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_queries.fetch_add(1, Ordering::Relaxed);
        }

        if event.is_dnssec_query() {
            self.dnssec_queries.fetch_add(1, Ordering::Relaxed);
        }

        self.total_response_time_us
            .fetch_add(event.response_time_us, Ordering::Relaxed);

        self.domain_counts
            .entry(event.domain.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);

        self.record_type_counts
            .entry(event.record_type)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        self.upstream_counts
            .entry(event.upstream_server.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Get total number of events
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Get successful query count
    pub fn successful_queries(&self) -> u64 {
        self.successful_queries.load(Ordering::Relaxed)
    }

    /// Get failed query count
    pub fn failed_queries(&self) -> u64 {
        self.failed_queries.load(Ordering::Relaxed)
    }

    /// Get DNSSEC query count
    pub fn dnssec_queries(&self) -> u64 {
        self.dnssec_queries.load(Ordering::Relaxed)
    }

    /// Get success rate (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.total_events();
        if total == 0 {
            return 0.0;
        }
        self.successful_queries() as f64 / total as f64
    }

    /// Get average response time in microseconds
    pub fn avg_response_time_us(&self) -> f64 {
        let total = self.total_events();
        if total == 0 {
            return 0.0;
        }
        self.total_response_time_us.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// Get average response time in milliseconds
    pub fn avg_response_time_ms(&self) -> f64 {
        self.avg_response_time_us() / 1000.0
    }

    /// Get query count for a specific domain
    pub fn domain_count(&self, domain: &str) -> u64 {
        self.domain_counts.get(domain).map(|v| *v).unwrap_or(0)
    }

    /// Get query count for a specific record type
    pub fn record_type_count(&self, record_type: RecordType) -> u64 {
        self.record_type_counts
            .get(&record_type)
            .map(|v| *v)
            .unwrap_or(0)
    }

    /// Get query count for a specific upstream server
    pub fn upstream_count(&self, upstream: &str) -> u64 {
        self.upstream_counts.get(upstream).map(|v| *v).unwrap_or(0)
    }

    /// Get top N domains by query count
    pub fn top_domains(&self, n: usize) -> Vec<(String, u64)> {
        let mut domains: Vec<_> = self
            .domain_counts
            .iter()
            .map(|entry| (entry.key().to_string(), *entry.value()))
            .collect();

        domains.sort_by(|a, b| b.1.cmp(&a.1));
        domains.truncate(n);
        domains
    }

    /// Get top N record types by query count
    pub fn top_record_types(&self, n: usize) -> Vec<(RecordType, u64)> {
        let mut types: Vec<_> = self
            .record_type_counts
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();

        types.sort_by(|a, b| b.1.cmp(&a.1));
        types.truncate(n);
        types
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_events.store(0, Ordering::Relaxed);
        self.successful_queries.store(0, Ordering::Relaxed);
        self.failed_queries.store(0, Ordering::Relaxed);
        self.dnssec_queries.store(0, Ordering::Relaxed);
        self.total_response_time_us.store(0, Ordering::Relaxed);
        self.domain_counts.clear();
        self.record_type_counts.clear();
        self.upstream_counts.clear();
    }
}

impl Default for QueryMetrics {
    fn default() -> Self {
        Self::new()
    }
}
