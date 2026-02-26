use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use super::custom_to_definition;
use crate::ports::{
    BlockFilterEnginePort, BlockedServiceRepository, CustomServiceRepository,
    ManagedDomainRepository, ServiceCatalogPort,
};

pub struct DeleteCustomServiceUseCase {
    custom_repo: Arc<dyn CustomServiceRepository>,
    catalog: Arc<dyn ServiceCatalogPort>,
    blocked_service_repo: Arc<dyn BlockedServiceRepository>,
    managed_domain_repo: Arc<dyn ManagedDomainRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteCustomServiceUseCase {
    pub fn new(
        custom_repo: Arc<dyn CustomServiceRepository>,
        catalog: Arc<dyn ServiceCatalogPort>,
        blocked_service_repo: Arc<dyn BlockedServiceRepository>,
        managed_domain_repo: Arc<dyn ManagedDomainRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            custom_repo,
            catalog,
            blocked_service_repo,
            managed_domain_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, service_id: &str) -> Result<(), DomainError> {
        if !service_id.starts_with("custom_") {
            return Err(DomainError::CustomServiceNotFound(service_id.to_string()));
        }

        let blocked_deleted = self
            .blocked_service_repo
            .delete_all_for_service(service_id)
            .await?;

        let domains_deleted = self
            .managed_domain_repo
            .delete_all_by_service(service_id)
            .await?;

        self.custom_repo.delete(service_id).await?;

        info!(
            service_id = %service_id,
            blocked_deleted = blocked_deleted,
            domains_deleted = domains_deleted,
            "Custom service deleted with cascade"
        );

        self.reload_catalog().await;

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after deleting custom service");
        }

        Ok(())
    }

    async fn reload_catalog(&self) {
        if let Ok(all) = self.custom_repo.get_all().await {
            let defs: Vec<_> = all.iter().map(custom_to_definition).collect();
            self.catalog.reload_custom(defs);
        }
    }
}
