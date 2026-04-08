use async_trait::async_trait;
use ferrous_dns_domain::{Config, DomainError};

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn save_local_records(&self, config: &Config) -> Result<(), DomainError>;
}
