use serde::Serialize;

/// Pi-hole v6 GET /api/history/clients response.
#[derive(Debug, Serialize)]
pub struct HistoryClientsResponse {
    pub clients: Vec<ClientHistoryEntry>,
}

#[derive(Debug, Serialize)]
pub struct ClientHistoryEntry {
    pub name: String,
    pub ip: String,
    pub total: u64,
}
