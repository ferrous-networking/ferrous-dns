use crate::ports::ConfigRepository;
use ferrous_dns_domain::{Config, DomainError};
use std::sync::Arc;

pub struct UpdateConfigUseCase {
    repository: Arc<dyn ConfigRepository>,
}

impl UpdateConfigUseCase {
    pub fn new(repository: Arc<dyn ConfigRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, config: &Config) -> Result<(), DomainError> {
        self.repository.save_config(config).await
    }
}
