use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
pub struct StatsQuery {
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "24h".to_string()
}

pub type QuerySourceStats = HashMap<String, u64>;

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

    pub queries_by_type: HashMap<String, u64>,
    pub most_queried_type: Option<String>,
    pub record_type_distribution: Vec<TypeDistribution>,
    pub top_10_types: Vec<TopType>,
    pub source_stats: QuerySourceStats,
}

#[derive(Serialize, Debug, Clone)]
pub struct TypeDistribution {
    pub record_type: String,
    pub percentage: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct TopType {
    pub record_type: String,
    pub count: u64,
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
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
            top_10_types: Vec::new(),
            source_stats: HashMap::new(),
        }
    }
}
