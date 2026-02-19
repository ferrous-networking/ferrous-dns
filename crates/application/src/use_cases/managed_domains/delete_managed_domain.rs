use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ManagedDomainRepository};

pub struct DeleteManagedDomainUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteManagedDomainUseCase {
    pub fn new(
        repo: Arc<dyn ManagedDomainRepository>,
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
            DomainError::ManagedDomainNotFound(format!("Managed domain {} not found", id))
        })?;

        self.repo.delete(id).await?;

        info!(domain_id = ?id, "Managed domain deleted successfully");

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after managed domain deletion");
        }

        Ok(())
    }
}
