use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct BlocklistQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedBlocklist {
    pub data: Vec<BlocklistResponse>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct BlocklistResponse {
    pub domain: String,
    pub added_at: String,
}
