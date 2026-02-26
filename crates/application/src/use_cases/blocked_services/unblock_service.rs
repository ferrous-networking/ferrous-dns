use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, BlockedServiceRepository, ManagedDomainRepository};

pub struct UnblockServiceUseCase {
    blocked_service_repo: Arc<dyn BlockedServiceRepository>,
    managed_domain_repo: Arc<dyn ManagedDomainRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UnblockServiceUseCase {
    pub fn new(
        blocked_service_repo: Arc<dyn BlockedServiceRepository>,
        managed_domain_repo: Arc<dyn ManagedDomainRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            blocked_service_repo,
            managed_domain_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, service_id: &str, group_id: i64) -> Result<(), DomainError> {
        self.blocked_service_repo
            .unblock_service(service_id, group_id)
            .await?;

        let deleted = self
            .managed_domain_repo
            .delete_by_service(service_id, group_id)
            .await?;

        info!(
            service_id = %service_id,
            group_id = group_id,
            domains_deleted = deleted,
            "Service unblocked"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after unblocking service");
        }

        Ok(())
    }
}
