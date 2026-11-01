use ferrous_dns_domain::Group;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GroupResponse {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub comment: Option<String>,
    pub is_default: bool,
    /// Whether the malware detectors check this group's queries. `false`
    /// exempts every client in the group.
    pub malware_detection_enabled: bool,
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
            malware_detection_enabled: group.malware_detection_enabled,
            client_count,
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
    /// Defaults to `true`.
    pub malware_detection_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
    pub malware_detection_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AssignGroupRequest {
    pub group_id: i64,
}
