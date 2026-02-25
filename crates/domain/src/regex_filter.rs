use crate::managed_domain::DomainAction;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexFilter {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub pattern: Arc<str>,
    pub action: DomainAction,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl RegexFilter {
    pub fn new(
        id: Option<i64>,
        name: Arc<str>,
        pattern: Arc<str>,
        action: DomainAction,
        group_id: i64,
        comment: Option<Arc<str>>,
        enabled: bool,
    ) -> Self {
        Self {
            id,
            name,
            pattern,
            action,
            group_id,
            comment,
            enabled,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Regex filter name cannot be empty".to_string());
        }
        if name.len() > 200 {
            return Err("Regex filter name cannot exceed 200 characters".to_string());
        }
        Ok(())
    }

    pub fn validate_pattern(pattern: &str) -> Result<(), String> {
        if pattern.is_empty() {
            return Err("Pattern cannot be empty".to_string());
        }
        if pattern.len() > 1000 {
            return Err("Pattern cannot exceed 1000 characters".to_string());
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
