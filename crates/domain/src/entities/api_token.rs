use crate::DomainError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Fewest characters a custom key may have. Pi-hole's keys are longer (44 for
/// a v6 app password, 64 for a v5 API token), and nothing throttles guesses.
pub const MIN_CUSTOM_KEY_CHARS: usize = 32;

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
    /// A custom key replaces the generated 256-bit one, so it must be long
    /// enough that guessing it is out of reach.
    pub fn validate_custom_key(key: &str) -> Result<(), DomainError> {
        if key.chars().count() < MIN_CUSTOM_KEY_CHARS {
            return Err(DomainError::InvalidInput(format!(
                "A custom token needs at least {MIN_CUSTOM_KEY_CHARS} characters"
            )));
        }
        Ok(())
    }

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
