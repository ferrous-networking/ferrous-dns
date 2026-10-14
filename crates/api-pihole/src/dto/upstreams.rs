use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/stats/upstreams response.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamsResponse {
    /// The `blocklist` and `cache` pseudo-entries first, then each upstream
    /// server by descending count, as FTL orders them.
    pub upstreams: Vec<UpstreamEntry>,
    pub forwarded_queries: u64,
    pub total_queries: u64,
}

/// One answer source: an upstream server, or the `blocklist` / `cache`
/// pseudo-entry (port -1).
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamEntry {
    pub ip: Option<String>,
    pub name: Option<String>,
    pub port: i32,
    pub count: u64,
    pub statistics: UpstreamStatistics,
}

/// Response time of an upstream in seconds. Ferrous keeps no per-server
/// timing, so both stay 0.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct UpstreamStatistics {
    pub response: f64,
    pub variance: f64,
}
