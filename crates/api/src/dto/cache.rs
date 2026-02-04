use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct CacheStatsResponse {
    pub total_entries: usize,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_refreshes: u64,
    pub hit_rate: f64,
    pub refresh_rate: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct CacheMetricsResponse {
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub optimistic_refreshes: u64,
    pub lazy_deletions: u64,
    pub compactions: u64,
    pub batch_evictions: u64,
    pub hit_rate: f64,
}
