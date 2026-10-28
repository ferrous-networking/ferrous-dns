use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct ManagedDomainQuery {
    /// Domains per page, 1 to 1000; default 100.
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    100
}

#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedManagedDomains {
    pub data: Vec<ManagedDomainResponse>,
    /// Every managed domain, across all pages.
    pub total: u64,
    /// Page size applied: the requested `limit`, clamped to 1..=1000.
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ManagedDomainResponse {
    pub id: i64,
    pub name: String,
    pub domain: String,
    #[schema(value_type = String)]
    pub action: &'static str,
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
            action: d.action.to_str(),
            group_id: d.group_id,
            comment: d.comment.as_ref().map(|s| s.to_string()),
            enabled: d.enabled,
            service_id: d.service_id.as_ref().map(|s| s.to_string()),
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Parses a request `action` field shared by managed domains and regex filters.
pub fn parse_action(value: &str) -> Result<DomainAction, DomainError> {
    value.parse()
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateManagedDomainRequest {
    pub name: String,
    pub domain: String,
    pub action: String,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateManagedDomainRequest {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub action: Option<String>,
    pub group_id: Option<i64>,
    /// Absent keeps the comment; `null` clears it.
    #[serde(default, deserialize_with = "crate::dto::source_common::double_option")]
    pub comment: Option<Option<String>>,
    pub enabled: Option<bool>,
}
