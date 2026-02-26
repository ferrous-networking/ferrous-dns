use ferrous_dns_domain::{CustomService, DomainError};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::CustomServiceRepository;

pub struct GetCustomServicesUseCase {
    custom_repo: Arc<dyn CustomServiceRepository>,
}

impl GetCustomServicesUseCase {
    pub fn new(custom_repo: Arc<dyn CustomServiceRepository>) -> Self {
        Self { custom_repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<CustomService>, DomainError> {
        self.custom_repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_service_id(
        &self,
        service_id: &str,
    ) -> Result<Option<CustomService>, DomainError> {
        self.custom_repo.get_by_service_id(service_id).await
    }
}
