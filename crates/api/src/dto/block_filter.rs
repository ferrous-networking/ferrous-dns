use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct BlockFilterStatsResponse {
    pub total_blocked_domains: usize,
}
