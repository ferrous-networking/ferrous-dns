use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, BlocklistSourceRepository};

pub struct DeleteBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl DeleteBlocklistSourceUseCase {
    pub fn new(repo: Arc<dyn BlocklistSourceRepository>) -> Self {
        Self {
            repo,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.block_filter_engine = Some(engine);
        self
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        self.repo.delete(id).await?;

        info!(source_id = ?id, "Blocklist source deleted successfully");

        if let Some(ref engine) = self.block_filter_engine {
            if let Err(e) = engine.reload().await {
                error!(error = %e, "Failed to reload block filter after blocklist source deletion");
            }
        }

        Ok(())
    }
}
