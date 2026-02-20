use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistSource {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub url: Option<Arc<str>>,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl WhitelistSource {
    pub fn new(
        id: Option<i64>,
        name: Arc<str>,
        url: Option<Arc<str>>,
        group_id: i64,
        comment: Option<Arc<str>>,
        enabled: bool,
    ) -> Self {
        Self {
            id,
            name,
            url,
            group_id,
            comment,
            enabled,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        crate::validators::validate_source_name(name, "Whitelist source")
    }

    pub fn validate_url(url: &Option<Arc<str>>) -> Result<(), String> {
        crate::validators::validate_url(url)
    }

    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        crate::validators::validate_comment(comment)
    }
}
