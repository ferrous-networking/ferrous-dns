use crate::ports::ConfigRepository;
use ferrous_dns_domain::{Config, DomainError};
use std::sync::Arc;

pub struct GetConfigUseCase {
    repository: Arc<dyn ConfigRepository>,
}

impl GetConfigUseCase {
    pub fn new(repository: Arc<dyn ConfigRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self) -> Result<Config, DomainError> {
        self.repository.get_config().await
    }
}
