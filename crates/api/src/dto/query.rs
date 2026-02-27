use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize, Debug)]
pub struct QueryParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub cursor: Option<i64>,
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug)]
pub struct PaginatedQueries {
    pub data: Vec<QueryResponse>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub next_cursor: Option<i64>,
}

fn default_period() -> String {
    "24h".to_string()
}

#[derive(Serialize, Debug, Clone)]
pub struct QueryResponse {
    pub timestamp: String,
    pub domain: Arc<str>,
    pub client: String,
    pub client_hostname: Option<Arc<str>>,
    #[serde(rename = "type")]
    pub record_type: &'static str,
    pub blocked: bool,
    pub response_time_us: Option<u64>,
    pub cache_hit: bool,
    pub cache_refresh: bool,
    pub dnssec_status: Option<&'static str>,
    pub upstream_server: Option<Arc<str>>,
    pub upstream_pool: Option<Arc<str>>,
    pub query_source: &'static str,
    pub block_source: Option<&'static str>,
    pub response_status: Option<&'static str>,
}
