use std::sync::Arc;
use tracing::instrument;

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Lists all API tokens (metadata only — no raw keys or hashes).
pub struct GetApiTokensUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl GetApiTokensUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<Vec<ApiToken>, DomainError> {
        self.repo.get_all().await
    }
}
