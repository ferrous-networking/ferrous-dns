use ferrous_dns_domain::{BlocklistSource, DomainError};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::BlocklistSourceRepository;

pub struct GetBlocklistSourcesUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
}

impl GetBlocklistSourcesUseCase {
    pub fn new(repo: Arc<dyn BlocklistSourceRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        self.repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        self.repo.get_by_id(id).await
    }
}
