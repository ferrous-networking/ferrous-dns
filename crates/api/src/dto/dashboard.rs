use serde::{Deserialize, Serialize};

use super::{CacheStatsResponse, QueryRateResponse, StatsResponse, TimelineResponse};

fn default_period() -> String {
    "24h".to_string()
}

#[derive(Deserialize, Debug)]
pub struct DashboardQuery {
    #[serde(default = "default_period")]
    pub period: String,
    #[serde(default)]
    pub include_timeline: bool,
}

#[derive(Serialize, Debug)]
pub struct DashboardResponse {
    pub stats: StatsResponse,
    pub rate: QueryRateResponse,
    pub cache_stats: CacheStatsResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineResponse>,
}
