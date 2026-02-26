use ferrous_dns_domain::{CustomService, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use super::custom_to_definition;
use crate::ports::{
    BlockFilterEnginePort, BlockedServiceRepository, CustomServiceRepository,
    ManagedDomainRepository, ServiceCatalogPort,
};

pub struct UpdateCustomServiceUseCase {
    custom_repo: Arc<dyn CustomServiceRepository>,
    catalog: Arc<dyn ServiceCatalogPort>,
    managed_domain_repo: Arc<dyn ManagedDomainRepository>,
    blocked_service_repo: Arc<dyn BlockedServiceRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateCustomServiceUseCase {
    pub fn new(
        custom_repo: Arc<dyn CustomServiceRepository>,
        catalog: Arc<dyn ServiceCatalogPort>,
        managed_domain_repo: Arc<dyn ManagedDomainRepository>,
        blocked_service_repo: Arc<dyn BlockedServiceRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            custom_repo,
            catalog,
            managed_domain_repo,
            blocked_service_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        service_id: &str,
        name: Option<String>,
        category_name: Option<String>,
        domains: Option<Vec<String>>,
    ) -> Result<CustomService, DomainError> {
        if !service_id.starts_with("custom_") {
            return Err(DomainError::CustomServiceNotFound(service_id.to_string()));
        }

        let domains_changed = domains.is_some();

        let updated = self
            .custom_repo
            .update(service_id, name, category_name, domains)
            .await?;

        if domains_changed {
            self.rebuild_managed_domains(service_id, &updated).await?;
        }

        self.reload_catalog().await;

        info!(service_id = %service_id, "Custom service updated");
        Ok(updated)
    }

    async fn rebuild_managed_domains(
        &self,
        service_id: &str,
        updated: &CustomService,
    ) -> Result<(), DomainError> {
        let blocked = self.blocked_service_repo.get_all_blocked().await?;
        let groups_with_service: Vec<i64> = blocked
            .into_iter()
            .filter(|b| b.service_id.as_ref() == service_id)
            .map(|b| b.group_id)
            .collect();

        for group_id in groups_with_service {
            self.managed_domain_repo
                .delete_by_service(service_id, group_id)
                .await?;

            let service_name = updated.name.to_string();
            let normalized: Vec<(String, String)> = updated
                .domains
                .iter()
                .map(|d| {
                    let name = format!("[{}] {}", service_name, d);
                    (name, d.to_string())
                })
                .collect();

            self.managed_domain_repo
                .bulk_create_for_service(service_id, group_id, normalized)
                .await?;
        }

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after updating custom service");
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
