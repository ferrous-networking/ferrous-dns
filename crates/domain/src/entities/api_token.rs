use crate::DomainError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A named API token for machine-to-machine authentication.
///
/// Only the SHA-256 hash of the key is stored, and validation looks it up; the
/// key itself is shown once, when it is created. The `key_prefix` (first 8
/// chars) helps users identify which token is which in listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub key_prefix: Arc<str>,
    pub key_hash: Arc<str>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl ApiToken {
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        if name.is_empty() {
            return Err(DomainError::InvalidInput(
                "Token name cannot be empty".to_string(),
            ));
        }
        if name.len() > 100 {
            return Err(DomainError::InvalidInput(
                "Token name cannot exceed 100 characters".to_string(),
            ));
        }
        let valid = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
        if !valid {
            return Err(DomainError::InvalidInput(
                "Token name can only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
