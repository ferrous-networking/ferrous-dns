use crate::dns_record::RecordType;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Source/origin of a DNS query (Phase 5: Internal Query Logging)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuerySource {
    /// Query from a DNS client
    Client,
    /// Internal query made by the server (e.g., for recursive resolution)
    Internal,
    /// Internal query for DNSSEC validation (DS, DNSKEY, RRSIG, etc.)
    DnssecValidation,
}

impl QuerySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuerySource::Client => "client",
            QuerySource::Internal => "internal",
            QuerySource::DnssecValidation => "dnssec_validation",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(QuerySource::Client),
            "internal" => Some(QuerySource::Internal),
            "dnssec_validation" => Some(QuerySource::DnssecValidation),
            _ => None,
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(self, QuerySource::Internal | QuerySource::DnssecValidation)
    }
}

impl Default for QuerySource {
    fn default() -> Self {
        QuerySource::Client
    }
}

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: Option<i64>,
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    pub dnssec_status: Option<&'static str>,
    pub upstream_server: Option<String>,
    pub response_status: Option<&'static str>,
    pub timestamp: Option<String>,

    /// Phase 5: Source of the query (client, internal, dnssec_validation)
    pub query_source: QuerySource,
}

/// Phase 4: Enhanced QueryStats with analytics
#[derive(Debug, Clone)]
pub struct QueryStats {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub unique_clients: u64,
    pub uptime_seconds: u64,
    pub cache_hit_rate: f64,
    pub avg_query_time_ms: f64,
    pub avg_cache_time_ms: f64,
    pub avg_upstream_time_ms: f64,

    // Phase 4: Analytics - Distribution by type
    pub queries_by_type: HashMap<RecordType, u64>,
    pub most_queried_type: Option<RecordType>,
    pub record_type_distribution: Vec<(RecordType, f64)>, // (type, percentage)
}

impl QueryStats {
    /// Phase 4: Calculate analytics from queries
    pub fn with_analytics(mut self, queries_by_type: HashMap<RecordType, u64>) -> Self {
        self.queries_by_type = queries_by_type.clone();

        // Find most queried type
        self.most_queried_type = queries_by_type
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(record_type, _)| *record_type);

        // Calculate distribution percentages
        let total: u64 = queries_by_type.values().sum();
        if total > 0 {
            let mut distribution: Vec<(RecordType, f64)> = queries_by_type
                .iter()
                .map(|(record_type, count)| {
                    let percentage = (*count as f64 / total as f64) * 100.0;
                    (*record_type, percentage)
                })
                .collect();

            // Sort by percentage descending
            distribution.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            self.record_type_distribution = distribution;
        } else {
            self.record_type_distribution = Vec::new();
        }

        self
    }

    /// Phase 4: Get top N most queried types
    pub fn top_types(&self, n: usize) -> Vec<(RecordType, u64)> {
        let mut types: Vec<(RecordType, u64)> = self
            .queries_by_type
            .iter()
            .map(|(rt, count)| (*rt, *count))
            .collect();

        types.sort_by(|a, b| b.1.cmp(&a.1));
        types.truncate(n);
        types
    }

    /// Phase 4: Get percentage for specific type
    pub fn type_percentage(&self, record_type: RecordType) -> f64 {
        self.record_type_distribution
            .iter()
            .find(|(rt, _)| *rt == record_type)
            .map(|(_, pct)| *pct)
            .unwrap_or(0.0)
    }

    /// Phase 4: Get count for specific type
    pub fn type_count(&self, record_type: RecordType) -> u64 {
        *self.queries_by_type.get(&record_type).unwrap_or(&0)
    }
}

impl Default for QueryStats {
    fn default() -> Self {
        Self {
            queries_total: 0,
            queries_blocked: 0,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_updates: u64,
    pub total_evictions: u64,
    pub hit_rate: f64,
    pub avg_ttl_seconds: u64,
}
