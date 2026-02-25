use crate::block_source::BlockSource;
use crate::dns_record::RecordType;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuerySource {
    #[default]
    Client,
    Internal,
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

    pub fn is_internal(&self) -> bool {
        matches!(self, QuerySource::Internal | QuerySource::DnssecValidation)
    }
}

impl std::fmt::Display for QuerySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct ParseQuerySourceError {
    invalid: String,
}

impl std::fmt::Display for ParseQuerySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid query source: '{}'", self.invalid)
    }
}

impl std::error::Error for ParseQuerySourceError {}

impl FromStr for QuerySource {
    type Err = ParseQuerySourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client" => Ok(QuerySource::Client),
            "internal" => Ok(QuerySource::Internal),
            "dnssec_validation" => Ok(QuerySource::DnssecValidation),
            _ => Err(ParseQuerySourceError {
                invalid: s.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: Option<i64>,
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub client_hostname: Option<Arc<str>>,
    pub blocked: bool,
    pub response_time_us: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    pub dnssec_status: Option<&'static str>,
    pub upstream_server: Option<String>,
    pub response_status: Option<&'static str>,
    pub timestamp: Option<String>,

    pub query_source: QuerySource,

    pub group_id: Option<i64>,
    pub block_source: Option<BlockSource>,
}

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

    pub source_stats: HashMap<String, u64>,

    pub queries_by_type: HashMap<RecordType, u64>,
    pub most_queried_type: Option<RecordType>,
    pub record_type_distribution: Vec<(RecordType, f64)>,
}

impl QueryStats {
    pub fn with_analytics(mut self, queries_by_type: HashMap<RecordType, u64>) -> Self {
        self.queries_by_type = queries_by_type.clone();

        self.most_queried_type = queries_by_type
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(record_type, _)| *record_type);

        let total: u64 = queries_by_type.values().sum();

        if total > 0 {
            let mut distribution: Vec<(RecordType, f64)> = queries_by_type
                .iter()
                .map(|(record_type, count)| {
                    let percentage = (*count as f64 / total as f64) * 100.0;
                    (*record_type, percentage)
                })
                .collect();

            distribution.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            self.record_type_distribution = distribution;
        } else {
            self.record_type_distribution = Vec::new();
        }

        self
    }

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

    pub fn type_percentage(&self, record_type: RecordType) -> f64 {
        self.record_type_distribution
            .iter()
            .find(|(rt, _)| *rt == record_type)
            .map(|(_, pct)| *pct)
            .unwrap_or(0.0)
    }

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
            source_stats: HashMap::new(),
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
