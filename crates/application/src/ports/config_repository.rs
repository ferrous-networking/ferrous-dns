use async_trait::async_trait;
use ferrous_dns_domain::{DnsConfig, DomainError};

#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn get_config(&self) -> Result<DnsConfig, DomainError>;
    async fn save_config(&self, config: &DnsConfig) -> Result<(), DomainError>;
}
