use ferrous_dns_domain::Group;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResponse {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub comment: Option<String>,
    pub is_default: bool,
    pub client_count: Option<u64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl GroupResponse {
    pub fn from_group(group: Group, client_count: Option<u64>) -> Self {
        Self {
            id: group.id.unwrap_or(0),
            name: group.name.to_string(),
            enabled: group.enabled,
            comment: group.comment.as_ref().map(|s| s.to_string()),
            is_default: group.is_default,
            client_count,
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssignGroupRequest {
    pub group_id: i64,
}
