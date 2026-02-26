use ferrous_dns_domain::ManagedDomain;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDomainResponse {
    pub id: i64,
    pub name: String,
    pub domain: String,
    pub action: String,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
    pub service_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl ManagedDomainResponse {
    pub fn from_domain(d: ManagedDomain) -> Self {
        Self {
            id: d.id.unwrap_or(0),
            name: d.name.to_string(),
            domain: d.domain.to_string(),
            action: d.action.to_str().to_string(),
            group_id: d.group_id,
            comment: d.comment.as_ref().map(|s| s.to_string()),
            enabled: d.enabled,
            service_id: d.service_id.as_ref().map(|s| s.to_string()),
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateManagedDomainRequest {
    pub name: String,
    pub domain: String,
    pub action: String,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateManagedDomainRequest {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub action: Option<String>,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}
