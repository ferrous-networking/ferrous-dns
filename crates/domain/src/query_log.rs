use crate::dns_record::RecordType;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: Option<i64>,
    pub domain: String,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,  // NEW: Optimistic refresh
    pub dnssec_status: Option<String>,  // NEW: "Secure", "Insecure", "Bogus", "Indeterminate"
    pub timestamp: Option<String>,
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
}

// NEW: Cache-specific statistics
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
