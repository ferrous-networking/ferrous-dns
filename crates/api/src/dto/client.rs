use ferrous_dns_domain::Client;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ClientResponse {
    pub id: i64,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub query_count: u64,
    pub group_id: Option<i64>,
}

impl From<Client> for ClientResponse {
    fn from(c: Client) -> Self {
        Self {
            id: c.id.unwrap_or(0),
            ip_address: c.ip_address.to_string(),
            mac_address: c.mac_address.map(|s| s.to_string()),
            hostname: c.hostname.map(|s| s.to_string()),
            first_seen: c.first_seen.unwrap_or_default(),
            last_seen: c.last_seen.unwrap_or_default(),
            query_count: c.query_count,
            group_id: c.group_id,
        }
    }
}

#[derive(Serialize, Debug, ToSchema)]
pub struct ClientStatsResponse {
    pub total_clients: u64,
    pub active_24h: u64,
    pub active_7d: u64,
    pub with_mac: u64,
    pub with_hostname: u64,
}

#[derive(Deserialize, Debug, IntoParams)]
pub struct ClientsQuery {
    /// Clients per page, 1 to 1000; default 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    /// Only clients seen within the last N days.
    #[serde(default)]
    pub active_days: Option<u32>,
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedClients {
    pub data: Vec<ClientResponse>,
    /// Clients matching `active_days`, or every client without it.
    pub total: u64,
    /// Page size applied: the requested `limit`, clamped to 1..=1000.
    pub limit: u32,
    pub offset: u32,
}

fn default_limit() -> u32 {
    100
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct UpdateClientRequest {
    pub hostname: Option<String>,
    pub group_id: Option<i64>,
}
