use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{ApiKeyMaterial, ApiTokenRepository};
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

        // An empty key keeps the current one, matching create's "empty means not provided".
        let new_key = custom_token
            .filter(|token| !token.is_empty())
            .map(super::key_material);
        let updated = self
            .repo
            .update(
                id,
                name,
                new_key
                    .as_ref()
                    .map(|(prefix, hash)| ApiKeyMaterial { prefix, hash }),
            )
            .await?;

        info!(
            id = id,
            name = name,
            key_changed = new_key.is_some(),
            "API token updated"
        );
        Ok(updated)
    }
}
