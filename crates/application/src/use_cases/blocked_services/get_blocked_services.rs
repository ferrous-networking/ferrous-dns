use ferrous_dns_domain::{BlockedService, DomainError};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::BlockedServiceRepository;

pub struct GetBlockedServicesUseCase {
    repo: Arc<dyn BlockedServiceRepository>,
}

impl GetBlockedServicesUseCase {
    pub fn new(repo: Arc<dyn BlockedServiceRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn get_for_group(&self, group_id: i64) -> Result<Vec<BlockedService>, DomainError> {
        self.repo.get_blocked_for_group(group_id).await
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<BlockedService>, DomainError> {
        self.repo.get_all_blocked().await
    }
}
