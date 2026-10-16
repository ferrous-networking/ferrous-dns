use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::{CacheStatsResponse, QueryRateResponse, StatsResponse, TimelineResponse};

#[derive(Deserialize, Debug, IntoParams)]
pub struct DashboardQuery {
    #[serde(default = "crate::utils::default_period")]
    pub period: String,
    #[serde(default)]
    pub include_timeline: bool,
}

#[derive(Serialize, Debug, ToSchema)]
pub struct TopBlockedDomain {
    pub domain: String,
    pub count: u64,
}

#[derive(Serialize, Debug, ToSchema)]
pub struct TopClient {
    pub ip: String,
    pub hostname: Option<String>,
    pub count: u64,
}

#[derive(Serialize, Debug, ToSchema)]
pub struct DashboardResponse {
    pub stats: StatsResponse,
    pub rate: QueryRateResponse,
    pub cache_stats: CacheStatsResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineResponse>,
    pub top_blocked_domains: Vec<TopBlockedDomain>,
    pub top_clients: Vec<TopClient>,
    /// Whether malware detection runs: the master switch as of the last restart.
    pub malware_detection_enabled: bool,
}
