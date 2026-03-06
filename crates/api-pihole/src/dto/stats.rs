use serde::Serialize;
use std::collections::HashMap;

/// Pi-hole v6 GET /api/stats/summary response.
#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub queries: QuerySummary,
    pub clients: ClientSummary,
    pub gravity: GravitySummary,
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct QuerySummary {
    pub total: u64,
    pub blocked: u64,
    pub percent_blocked: f64,
    pub unique_domains: u64,
    pub forwarded: u64,
    pub cached: u64,
    pub frequency: f64,
    pub types: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct ClientSummary {
    pub active: u64,
    pub total: u64,
}

#[derive(Debug, Serialize)]
pub struct GravitySummary {
    pub domains_being_blocked: u64,
}

/// Pi-hole v6 GET /api/stats/history response.
///
/// Each bucket covers 10 minutes. The full 24h window yields 144 buckets.
#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub history: Vec<HistoryBucket>,
}

#[derive(Debug, Serialize)]
pub struct HistoryBucket {
    pub timestamp: i64,
    pub total: u64,
    pub blocked: u64,
}

/// Pi-hole v6 GET /api/stats/top_blocked response.
#[derive(Debug, Serialize)]
pub struct TopBlockedResponse {
    pub top_blocked: HashMap<String, u64>,
}

/// Pi-hole v6 GET /api/stats/top_clients response.
#[derive(Debug, Serialize)]
pub struct TopClientsResponse {
    /// Key format: `"<ip>|<hostname>"` (hostname empty string when unknown).
    pub top_sources: HashMap<String, u64>,
}

/// Pi-hole v6 GET /api/stats/query_types response.
#[derive(Debug, Serialize)]
pub struct QueryTypesResponse {
    /// Keys are DNS record type names (e.g. "A", "AAAA", "MX").
    /// Values are percentages (0.0–100.0).
    pub querytypes: HashMap<String, f64>,
}
