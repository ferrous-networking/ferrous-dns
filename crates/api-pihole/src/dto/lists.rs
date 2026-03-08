use serde::{Deserialize, Serialize};

/// Pi-hole v6 adlist/list entry.
#[derive(Debug, Serialize)]
pub struct PiholeListEntry {
    pub id: i64,
    pub address: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub r#type: u8,
    pub groups: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
    pub number: u64,
    pub status: u8,
}

/// Pi-hole v6 POST /api/lists request.
#[derive(Debug, Deserialize)]
pub struct CreateListRequest {
    pub address: String,
    pub comment: Option<String>,
    pub r#type: Option<u8>,
    pub groups: Option<Vec<i64>>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 list response envelope.
#[derive(Debug, Serialize)]
pub struct ListsResponse {
    pub lists: Vec<PiholeListEntry>,
}
