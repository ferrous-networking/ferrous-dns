use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct QueryParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_limit() -> u32 {
    10000
}

#[derive(Serialize, Debug)]
pub struct PaginatedQueries {
    pub data: Vec<QueryResponse>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

fn default_period() -> String {
    "24h".to_string()
}

#[derive(Serialize, Debug, Clone)]
pub struct QueryResponse {
    pub timestamp: String,
    pub domain: String,
    pub client: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    pub dnssec_status: Option<String>,
    pub upstream_server: Option<String>,
    pub query_source: String,
    /// Which filter layer blocked this query: "blocklist", "managed_domain", "regex_filter", or null
    pub block_source: Option<String>,
}
