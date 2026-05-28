use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct BlockFilterStatsResponse {
    pub total_blocked_domains: usize,
}
