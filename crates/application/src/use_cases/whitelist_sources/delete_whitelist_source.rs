use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::WhitelistSourceRepository;

pub struct DeleteWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
}

impl DeleteWhitelistSourceUseCase {
    pub fn new(repo: Arc<dyn WhitelistSourceRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo.get_by_id(id).await?.ok_or_else(|| {
            DomainError::WhitelistSourceNotFound(format!("Whitelist source {} not found", id))
        })?;

        self.repo.delete(id).await?;

        info!(source_id = ?id, "Whitelist source deleted successfully");

        Ok(())
    }
}
