use crate::ports::{QueryLogStorage, QueryLogStorageRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetQueryLogStorageUseCase {
    repository: Arc<dyn QueryLogStorageRepository>,
}

impl GetQueryLogStorageUseCase {
    pub fn new(repository: Arc<dyn QueryLogStorageRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<QueryLogStorage, DomainError> {
        self.repository.get_storage(period_hours).await
    }
}
