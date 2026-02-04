use crate::ports::BlocklistRepository;
use ferrous_dns_domain::{blocklist::BlockedDomain, DomainError};
use std::sync::Arc;

pub struct GetBlocklistUseCase {
    repository: Arc<dyn BlocklistRepository>,
}

impl GetBlocklistUseCase {
    pub fn new(repository: Arc<dyn BlocklistRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self) -> Result<Vec<BlockedDomain>, DomainError> {
        self.repository.get_all().await
    }
}
