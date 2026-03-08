use crate::DomainError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A named API token for machine-to-machine authentication.
///
/// The raw token value is persisted for admin display (like a password manager).
/// The SHA-256 hash is used for runtime validation. The `key_prefix` (first 8 chars)
/// helps users identify which token is which in listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub key_prefix: Arc<str>,
    pub key_hash: Arc<str>,
    /// The raw token value, persisted for admin display.
    pub key_raw: Option<Arc<str>>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl ApiToken {
    pub fn new(name: Arc<str>, key_prefix: Arc<str>, key_hash: Arc<str>) -> Self {
        Self {
            id: None,
            name,
            key_prefix,
            key_hash,
            key_raw: None,
            created_at: None,
            last_used_at: None,
        }
    }

    /// Validates that a token name meets naming constraints.
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        if name.is_empty() {
            return Err(DomainError::ConfigError(
                "Token name cannot be empty".to_string(),
            ));
        }
        if name.len() > 100 {
            return Err(DomainError::ConfigError(
                "Token name cannot exceed 100 characters".to_string(),
            ));
        }
        let valid = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
        if !valid {
            return Err(DomainError::ConfigError(
                "Token name can only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
