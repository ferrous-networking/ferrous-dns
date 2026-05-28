use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pi-hole v6 client entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeClientEntry {
    pub id: i64,
    pub ip: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub groups: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
}

/// Pi-hole v6 POST /api/clients request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClientRequest {
    pub ip: String,
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
}

/// Pi-hole v6 PUT /api/clients/:client request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    pub comment: Option<String>,
    pub groups: Option<Vec<i64>>,
}

/// Pi-hole v6 clients list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientsResponse {
    pub clients: Vec<PiholeClientEntry>,
}

/// Pi-hole v6 GET /api/clients/_suggestions response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSuggestionsResponse {
    pub suggestions: Vec<String>,
}
