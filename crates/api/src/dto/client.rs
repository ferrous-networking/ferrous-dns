use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct ClientResponse {
    pub id: i64,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub query_count: u64,
}

#[derive(Serialize, Debug)]
pub struct ClientStatsResponse {
    pub total_clients: u64,
    pub active_24h: u64,
    pub active_7d: u64,
    pub with_mac: u64,
    pub with_hostname: u64,
}

#[derive(Deserialize, Debug)]
pub struct ClientsQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default)]
    pub active_days: Option<u32>,
}

fn default_limit() -> u32 {
    100
}
