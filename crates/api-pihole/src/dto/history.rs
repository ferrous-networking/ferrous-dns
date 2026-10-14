use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/history/clients response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryClientsResponse {
    /// The same 145 ten-minute buckets as `/history`.
    pub history: Vec<ClientHistoryBucket>,
    /// Keyed by client IP, plus `others` when clients were folded into it.
    pub clients: BTreeMap<String, HistoryClient>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientHistoryBucket {
    pub timestamp: i64,
    /// Queries per client IP in this bucket; `others` sums the clients
    /// beyond `N` and is always present.
    pub data: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HistoryClient {
    pub name: Option<String>,
    pub total: u64,
}
