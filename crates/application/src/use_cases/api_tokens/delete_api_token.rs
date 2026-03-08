use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::DomainError;

/// Revokes (deletes) an API token by ID.
pub struct DeleteApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl DeleteApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo.delete(id).await?;
        info!(id = id, "API token revoked");
        Ok(())
    }
}
