use serde::Serialize;
use std::collections::HashMap;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/stats/summary response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SummaryResponse {
    pub queries: QuerySummary,
    pub clients: ClientSummary,
    pub gravity: GravitySummary,
    #[schema(value_type = String)]
    pub status: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSummary {
    pub active: u64,
    pub total: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GravitySummary {
    pub domains_being_blocked: u64,
    pub last_update: i64,
}

/// Pi-hole v6 GET /api/stats/history response.
///
/// Each bucket covers 10 minutes. The full 24h window yields 144 buckets.
#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryResponse {
    pub history: Vec<HistoryBucket>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryBucket {
    pub timestamp: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
}

/// Pi-hole v6 GET /api/stats/top_domains response (also used for top_blocked).
#[derive(Debug, Serialize, ToSchema)]
pub struct TopDomainsResponse {
    pub domains: Vec<TopDomainEntry>,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

/// Single entry in the top domains array.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopDomainEntry {
    pub domain: String,
    pub count: u64,
}

/// Pi-hole v6 GET /api/stats/top_clients response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopClientsResponse {
    pub clients: Vec<TopClientEntry>,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

/// Single entry in the top clients array.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopClientEntry {
    pub ip: String,
    pub name: String,
    pub count: u64,
}

/// Pi-hole v6 GET /api/stats/query_types response.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueryTypesResponse {
    /// Keys are DNS record type names (e.g. "A", "AAAA", "MX").
    /// Values are percentages (0.0-100.0).
    pub querytypes: HashMap<String, f64>,
}

/// Pi-hole v6 GET /api/stats/recent_blocked response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecentBlockedResponse {
    pub domain: Option<String>,
}
