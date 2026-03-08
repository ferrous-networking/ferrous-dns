use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Updates an existing API token's name and optionally replaces its key
/// (e.g. importing a Pi-hole API key for seamless migration).
pub struct UpdateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl UpdateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self, custom_token))]
    pub async fn execute(
        &self,
        id: i64,
        name: &str,
        custom_token: Option<&str>,
    ) -> Result<ApiToken, DomainError> {
        ApiToken::validate_name(name)?;

        if let Some(existing) = self.repo.get_by_name(name).await? {
            if existing.id != Some(id) {
                return Err(DomainError::DuplicateApiTokenName(name.to_string()));
            }
        }

        let (key_prefix, key_hash, key_raw) = match custom_token {
            Some(token) => {
                let prefix = if token.len() >= 8 { &token[..8] } else { token };
                let hash = super::hash_token(token);
                (
                    Some(prefix.to_string()),
                    Some(hash),
                    Some(token.to_string()),
                )
            }
            None => (None, None, None),
        };

        let updated = self
            .repo
            .update(
                id,
                name,
                key_prefix.as_deref(),
                key_hash.as_deref(),
                key_raw.as_deref(),
            )
            .await?;

        info!(
            id = id,
            name = name,
            key_changed = custom_token.is_some(),
            "API token updated"
        );
        Ok(updated)
    }
}
