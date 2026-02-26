use ferrous_dns_domain::{BlockedService, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, BlockedServiceRepository, GroupRepository, ManagedDomainRepository,
    ServiceCatalogPort,
};

pub struct BlockServiceUseCase {
    blocked_service_repo: Arc<dyn BlockedServiceRepository>,
    managed_domain_repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    catalog: Arc<dyn ServiceCatalogPort>,
}

impl BlockServiceUseCase {
    pub fn new(
        blocked_service_repo: Arc<dyn BlockedServiceRepository>,
        managed_domain_repo: Arc<dyn ManagedDomainRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
        catalog: Arc<dyn ServiceCatalogPort>,
    ) -> Self {
        Self {
            blocked_service_repo,
            managed_domain_repo,
            group_repo,
            block_filter_engine,
            catalog,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        service_id: &str,
        group_id: i64,
    ) -> Result<BlockedService, DomainError> {
        let service = self
            .catalog
            .get_by_id(service_id)
            .ok_or_else(|| DomainError::ServiceNotFoundInCatalog(service_id.to_string()))?;

        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        let blocked = self
            .blocked_service_repo
            .block_service(service_id, group_id)
            .await?;

        let service_name = service.name.to_string();
        let rules = self.catalog.normalized_rules_for(service_id);
        let domains: Vec<(String, String)> = rules
            .into_iter()
            .map(|domain| {
                let name = format!("[{}] {}", service_name, domain);
                (name, domain)
            })
            .collect();

        let count = self
            .managed_domain_repo
            .bulk_create_for_service(service_id, group_id, domains)
            .await?;

        info!(
            service_id = %service_id,
            group_id = group_id,
            domains_created = count,
            "Service blocked"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after blocking service");
        }

        Ok(blocked)
    }
}
