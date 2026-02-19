use ferrous_dns_domain::RegexFilter;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexFilterResponse {
    pub id: i64,
    pub name: String,
    pub pattern: String,
    pub action: String,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl RegexFilterResponse {
    pub fn from_domain(f: RegexFilter) -> Self {
        Self {
            id: f.id.unwrap_or(0),
            name: f.name.to_string(),
            pattern: f.pattern.to_string(),
            action: f.action.to_str().to_string(),
            group_id: f.group_id,
            comment: f.comment.as_ref().map(|s| s.to_string()),
            enabled: f.enabled,
            created_at: f.created_at,
            updated_at: f.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRegexFilterRequest {
    pub name: String,
    pub pattern: String,
    pub action: String,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateRegexFilterRequest {
    pub name: Option<String>,
    pub pattern: Option<String>,
    pub action: Option<String>,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}
