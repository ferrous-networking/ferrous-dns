use async_trait::async_trait;
use ferrous_dns_domain::{Config, DomainError};

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn get_config(&self) -> Result<Config, DomainError>;
    async fn save_config(&self, config: &Config) -> Result<(), DomainError>;
    async fn save_local_records(&self, config: &Config) -> Result<(), DomainError>;
}
