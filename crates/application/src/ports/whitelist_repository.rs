use async_trait::async_trait;
use ferrous_dns_domain::{whitelist::WhitelistedDomain, DomainError};

#[async_trait]
pub trait WhitelistRepository: Send + Sync {
    async fn get_all(&self) -> Result<Vec<WhitelistedDomain>, DomainError>;
    async fn add_domain(&self, domain: &WhitelistedDomain) -> Result<(), DomainError>;
    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError>;
    async fn is_whitelisted(&self, domain: &str) -> Result<bool, DomainError>;
}
