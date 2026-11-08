use ferrous_dns_domain::DohId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DohIdResponse {
    pub id: i64,
    pub name: String,
    pub client_id: String,
    pub group_id: i64,
    pub group_name: Option<String>,
    pub comment: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl DohIdResponse {
    pub fn from_doh_id(entry: DohId, group_name: Option<String>) -> Self {
        Self {
            id: entry.id.unwrap_or(0),
            name: entry.name.to_string(),
            client_id: entry.client_id.to_string(),
            group_id: entry.group_id,
            group_name,
            comment: entry.comment.as_ref().map(|s| s.to_string()),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateDohIdRequest {
    pub name: String,
    /// Optional readable identifier (`a-z`, `0-9`, `-`, 1..=63 chars, no leading/trailing `-`).
    /// When omitted or `null`, a random UUID v4 is generated automatically.
    pub client_id: Option<String>,
    pub group_id: i64,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateDohIdRequest {
    pub name: String,
    /// Optional replacement identifier. When omitted or `null`, the existing `client_id` is kept.
    pub client_id: Option<String>,
    pub group_id: i64,
    pub comment: Option<String>,
}
