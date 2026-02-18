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
        if name.is_empty() {
            return Err("Whitelist source name cannot be empty".to_string());
        }

        if name.len() > 200 {
            return Err("Whitelist source name cannot exceed 200 characters".to_string());
        }

        Ok(())
    }

    pub fn validate_url(url: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(u) = url {
            if u.len() > 2048 {
                return Err("URL cannot exceed 2048 characters".to_string());
            }
            if !u.starts_with("http://") && !u.starts_with("https://") {
                return Err("URL must start with http:// or https://".to_string());
            }
        }
        Ok(())
    }

    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err("Comment cannot exceed 500 characters".to_string());
            }
        }
        Ok(())
    }
}
