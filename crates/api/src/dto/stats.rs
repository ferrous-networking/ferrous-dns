use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct StatsResponse {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub clients: u64,
    pub uptime: u64,
    pub cache_hit_rate: f64,
    pub avg_query_time_ms: f64,
    pub avg_cache_time_ms: f64,
    pub avg_upstream_time_ms: f64,
}

impl Default for StatsResponse {
    fn default() -> Self {
        Self {
            queries_total: 0,
            queries_blocked: 0,
            clients: 0,
            uptime: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
        }
    }
}
