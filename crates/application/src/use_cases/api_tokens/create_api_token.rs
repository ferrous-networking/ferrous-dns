use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Response returned when a new API token is created.
pub struct CreatedApiToken {
    /// The persisted token metadata (includes raw token for admin display).
    pub token: ApiToken,
    /// The raw token value.
    pub raw_token: String,
}

/// Creates a named API token with a generated or user-provided key.
///
/// Supports an optional `custom_token` for importing existing keys
/// (e.g. migrating from Pi-hole without reconfiguring all clients).
pub struct CreateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl CreateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self, custom_token))]
    pub async fn execute(
        &self,
        name: &str,
        custom_token: Option<&str>,
    ) -> Result<CreatedApiToken, DomainError> {
        ApiToken::validate_name(name)?;

        let raw_token = match custom_token {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => super::generate_token()?,
        };

        let key_prefix = if raw_token.len() >= 8 {
            &raw_token[..8]
        } else {
            &raw_token
        };
        let key_hash = super::hash_token(&raw_token);

        let token = self
            .repo
            .create(name, key_prefix, &key_hash, &raw_token)
            .await?;

        info!(
            name = name,
            imported = custom_token.is_some(),
            "API token created"
        );
        Ok(CreatedApiToken { token, raw_token })
    }
}
