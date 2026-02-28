use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct BlocklistQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug)]
pub struct PaginatedBlocklist {
    pub data: Vec<BlocklistResponse>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct BlocklistResponse {
    pub domain: String,
    pub added_at: String,
}
