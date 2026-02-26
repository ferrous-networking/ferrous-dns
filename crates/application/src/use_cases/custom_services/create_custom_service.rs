use ferrous_dns_domain::{CustomService, DomainError};
use std::sync::Arc;
use tracing::{info, instrument};

use super::custom_to_definition;
use crate::ports::{CustomServiceRepository, ServiceCatalogPort};

pub struct CreateCustomServiceUseCase {
    custom_repo: Arc<dyn CustomServiceRepository>,
    catalog: Arc<dyn ServiceCatalogPort>,
}

impl CreateCustomServiceUseCase {
    pub fn new(
        custom_repo: Arc<dyn CustomServiceRepository>,
        catalog: Arc<dyn ServiceCatalogPort>,
    ) -> Self {
        Self {
            custom_repo,
            catalog,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: &str,
        category_name: &str,
        domains: Vec<String>,
    ) -> Result<CustomService, DomainError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(DomainError::CustomServiceAlreadyExists(
                "Name cannot be empty".to_string(),
            ));
        }
        if domains.is_empty() {
            return Err(DomainError::CustomServiceAlreadyExists(
                "At least one domain is required".to_string(),
            ));
        }

        let slug: String = trimmed
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        let service_id = format!("custom_{}", slug);

        if self.catalog.get_by_id(&service_id).is_some() {
            return Err(DomainError::CustomServiceAlreadyExists(service_id));
        }

        let category = if category_name.trim().is_empty() {
            "Custom"
        } else {
            category_name.trim()
        };

        let cs = self
            .custom_repo
            .create(&service_id, trimmed, category, &domains)
            .await?;

        info!(service_id = %service_id, name = %trimmed, "Custom service created");

        self.reload_catalog().await;

        Ok(cs)
    }

    async fn reload_catalog(&self) {
        if let Ok(all) = self.custom_repo.get_all().await {
            let defs: Vec<_> = all.iter().map(custom_to_definition).collect();
            self.catalog.reload_custom(defs);
        }
    }
}
