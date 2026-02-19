use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, RegexFilterRepository};

pub struct DeleteRegexFilterUseCase {
    repo: Arc<dyn RegexFilterRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteRegexFilterUseCase {
    pub fn new(
        repo: Arc<dyn RegexFilterRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo.get_by_id(id).await?.ok_or_else(|| {
            DomainError::RegexFilterNotFound(format!("Regex filter {} not found", id))
        })?;

        self.repo.delete(id).await?;

        info!(filter_id = ?id, "Regex filter deleted successfully");

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after regex filter deletion");
        }

        Ok(())
    }
}
