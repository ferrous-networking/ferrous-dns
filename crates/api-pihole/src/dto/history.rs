use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/history/clients response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryClientsResponse {
    pub clients: Vec<ClientHistoryEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientHistoryEntry {
    pub name: String,
    pub ip: String,
    pub total: u64,
}
