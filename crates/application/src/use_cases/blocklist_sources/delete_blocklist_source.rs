use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::BlocklistSourceRepository;

pub struct DeleteBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
}

impl DeleteBlocklistSourceUseCase {
    pub fn new(repo: Arc<dyn BlocklistSourceRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo.get_by_id(id).await?.ok_or_else(|| {
            DomainError::BlocklistSourceNotFound(format!("Blocklist source {} not found", id))
        })?;

        self.repo.delete(id).await?;

        info!(source_id = ?id, "Blocklist source deleted successfully");

        Ok(())
    }
}
