use serde::Serialize;
use std::collections::HashMap;

/// Pi-hole v6 GET /api/stats/upstreams response.
#[derive(Debug, Serialize)]
pub struct UpstreamsResponse {
    pub upstreams: HashMap<String, u64>,
    pub forwarded_queries: u64,
    pub total_queries: u64,
}
