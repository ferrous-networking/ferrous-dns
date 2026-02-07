use serde::Serialize;

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
    pub upstream_server: Option<String>, // ✅ Which upstream server responded
}
