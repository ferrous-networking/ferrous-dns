use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct QueryParams {
    /// Rows per page, 1 to 1000; default 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    /// `next_cursor` of the previous page; takes precedence over `offset`,
    /// which the response then answers as 0.
    pub cursor: Option<i64>,
    #[serde(default = "crate::utils::default_period")]
    pub period: String,
    pub domain: Option<String>,
    pub category: Option<String>,
    pub client: Option<String>,
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    pub upstream: Option<String>,
    /// Filter by DNSSEC validation status: `any` (any validated row), `Secure`,
    /// `Insecure`, `Bogus`, or `Indeterminate` (case-insensitive).
    pub dnssec_status: Option<String>,
    /// Filter by DNS64 synthesis: `true` keeps only synthesized AAAA answers,
    /// `false` only non-synthesized rows.
    pub dns64: Option<bool>,
    /// Filter by the transport the client used: `udp`, `tcp`, `dot`, `doh` or
    /// `doq` (case-insensitive).
    pub protocol: Option<String>,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedQueries {
    pub data: Vec<QueryResponse>,
    /// Total records matching the applied filters.
    pub total: u64,
    /// Total records in the period (without filters).
    pub records_total: u64,
    /// Page size applied: the requested `limit`, clamped to 1..=1000.
    pub limit: u32,
    pub offset: u32,
    /// Pass as `cursor` for the next page; `null` on the last one.
    pub next_cursor: Option<i64>,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct QueryResponse {
    pub timestamp: String,
    #[schema(value_type = String)]
    pub domain: Arc<str>,
    pub client: String,
    #[schema(value_type = Option<String>)]
    pub client_hostname: Option<Arc<str>>,
    #[serde(rename = "type")]
    #[schema(value_type = String)]
    pub record_type: &'static str,
    pub blocked: bool,
    pub response_time_us: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    #[schema(value_type = Option<String>)]
    pub dnssec_status: Option<&'static str>,
    /// `true` when the AAAA answer was synthesized by DNS64 (RFC 6147).
    pub dns64_synthesized: bool,
    /// Resolved A/AAAA addresses of the answer, capped at the first few that
    /// were persisted. Empty for blocked queries and non-address record types.
    pub answers: Vec<String>,
    #[schema(value_type = Option<String>)]
    pub upstream_server: Option<Arc<str>>,
    #[schema(value_type = Option<String>)]
    pub upstream_pool: Option<Arc<str>>,
    #[schema(value_type = String)]
    pub query_source: &'static str,
    /// Transport the client used to reach the resolver: `udp`, `tcp`, `dot`,
    /// `doh` or `doq`. `null` for rows logged before this was recorded.
    #[schema(value_type = Option<String>)]
    pub protocol: Option<&'static str>,
    #[schema(value_type = Option<String>)]
    pub block_source: Option<&'static str>,
    #[schema(value_type = Option<String>)]
    pub response_status: Option<&'static str>,
    /// The query's part in coalescing: `leader` when identical queries that
    /// arrived while it was in flight shared its answer, `follower` when it
    /// got such a query's answer, `null` otherwise.
    #[schema(value_type = Option<String>)]
    pub coalesced: Option<&'static str>,
}
