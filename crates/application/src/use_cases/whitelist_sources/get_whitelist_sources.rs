use ferrous_dns_domain::{DomainError, WhitelistSource};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::WhitelistSourceRepository;

pub struct GetWhitelistSourcesUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
}

impl GetWhitelistSourcesUseCase {
    pub fn new(repo: Arc<dyn WhitelistSourceRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<WhitelistSource>, DomainError> {
        self.repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<WhitelistSource>, DomainError> {
        self.repo.get_by_id(id).await
    }
}
