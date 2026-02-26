use async_trait::async_trait;
use ferrous_dns_domain::{BlockedService, DomainError};

#[async_trait]
pub trait BlockedServiceRepository: Send + Sync {
    async fn block_service(
        &self,
        service_id: &str,
        group_id: i64,
    ) -> Result<BlockedService, DomainError>;

    async fn unblock_service(&self, service_id: &str, group_id: i64) -> Result<(), DomainError>;

    async fn get_blocked_for_group(
        &self,
        group_id: i64,
    ) -> Result<Vec<BlockedService>, DomainError>;

    async fn get_all_blocked(&self) -> Result<Vec<BlockedService>, DomainError>;

    async fn delete_all_for_service(&self, service_id: &str) -> Result<u64, DomainError>;
}
