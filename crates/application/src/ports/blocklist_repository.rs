use async_trait::async_trait;
use ferrous_dns_domain::{blocklist::BlockedDomain, DomainError};

#[async_trait]
pub trait BlocklistRepository: Send + Sync {
    async fn get_all(&self) -> Result<Vec<BlockedDomain>, DomainError>;
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<BlockedDomain>, u64), DomainError>;
    async fn add_domain(&self, domain: &BlockedDomain) -> Result<(), DomainError>;
    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError>;
    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError>;
}
