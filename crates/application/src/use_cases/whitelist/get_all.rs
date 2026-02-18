use crate::ports::WhitelistRepository;
use ferrous_dns_domain::{whitelist::WhitelistedDomain, DomainError};
use std::sync::Arc;

pub struct GetWhitelistUseCase {
    repository: Arc<dyn WhitelistRepository>,
}

impl GetWhitelistUseCase {
    pub fn new(repository: Arc<dyn WhitelistRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self) -> Result<Vec<WhitelistedDomain>, DomainError> {
        self.repository.get_all().await
    }
}
