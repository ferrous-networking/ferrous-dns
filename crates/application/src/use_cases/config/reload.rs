use ferrous_dns_domain::{Config, DomainError};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct ReloadConfigUseCase {
    config: Arc<RwLock<Config>>,
}

impl ReloadConfigUseCase {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        Self { config }
    }

    pub async fn execute(&self, config_path: &str) -> Result<Config, DomainError> {
        let new_config = Config::load(Some(config_path), Default::default())
            .map_err(|e| DomainError::ConfigError(format!("Config load error: {}", e)))?;

        new_config
            .validate()
            .map_err(|e| DomainError::ConfigError(format!("Config validation error: {}", e)))?;

        {
            let mut config = self.config.write().await;
            *config = new_config.clone();
        }

        info!("Configuration reloaded successfully from: {}", config_path);

        Ok(new_config)
    }
}
