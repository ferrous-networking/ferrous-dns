use async_trait::async_trait;
use ferrous_dns_application::ports::ConfigRepository;
use ferrous_dns_domain::{Config, DomainError};

pub struct TomlConfigRepository {
    config_path: String,
}

impl TomlConfigRepository {
    pub fn new(config_path: String) -> Self {
        Self { config_path }
    }
}

#[async_trait]
impl ConfigRepository for TomlConfigRepository {
    async fn save_local_records(&self, config: &Config) -> Result<(), DomainError> {
        super::config_persistence::save_local_records_to_file(config, &self.config_path)
            .map_err(|e| DomainError::ConfigError(e.to_string()))
    }
}
