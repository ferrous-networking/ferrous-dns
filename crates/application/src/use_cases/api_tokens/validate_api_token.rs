use std::sync::Arc;
use tracing::instrument;

use crate::ports::ApiTokenRepository;
use crate::use_cases::auth::session_factory::sha256_hex;
use ferrous_dns_domain::DomainError;

/// Validates a raw API token against stored hashes.
///
/// On success, updates `last_used_at` and returns the token ID.
pub struct ValidateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl ValidateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    /// Validates the raw token by hashing it and looking up the hash in the database.
    /// Returns `Ok(token_id)` on match, `Err(InvalidCredentials)` otherwise.
    #[instrument(skip(self, raw_token))]
    pub async fn execute(&self, raw_token: &str) -> Result<i64, DomainError> {
        // An empty `X-Api-Key` must never match, even if an empty key was stored.
        if raw_token.is_empty() {
            return Err(DomainError::InvalidCredentials);
        }
        let incoming_hash = sha256_hex(raw_token);

        match self.repo.get_id_by_hash(&incoming_hash).await? {
            Some(id) => {
                self.repo.update_last_used(id).await?;
                Ok(id)
            }
            None => Err(DomainError::InvalidCredentials),
        }
    }
}
