use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct QueryParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub cursor: Option<i64>,
    #[serde(default = "default_period")]
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
    pub limit: u32,
    pub offset: u32,
    pub next_cursor: Option<i64>,
}

fn default_period() -> String {
    "24h".to_string()
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
    #[schema(value_type = Option<String>)]
    pub block_source: Option<&'static str>,
    #[schema(value_type = Option<String>)]
    pub response_status: Option<&'static str>,
}
