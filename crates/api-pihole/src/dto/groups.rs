use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pi-hole v6 group entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PiholeGroupEntry {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_modified: Option<String>,
}

/// Pi-hole v6 POST /api/groups request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 PUT /api/groups/:name request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// Pi-hole v6 groups list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupsResponse {
    pub groups: Vec<PiholeGroupEntry>,
}
