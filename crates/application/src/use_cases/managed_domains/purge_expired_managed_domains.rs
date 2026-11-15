use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ManagedDomainRepository};

/// Deletes the managed domains whose expiry has passed, and reloads the block
/// filter when that removed any.
pub struct PurgeExpiredManagedDomainsUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl PurgeExpiredManagedDomainsUseCase {
    pub fn new(
        repo: Arc<dyn ManagedDomainRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            block_filter_engine,
        }
    }

    /// Returns how many rules were deleted.
    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<u64, DomainError> {
        let deleted = self.repo.delete_expired().await?;
        if deleted == 0 {
            return Ok(0);
        }

        info!(deleted, "Expired managed domains removed");

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after removing expired managed domains");
        }

        Ok(deleted)
    }
}
