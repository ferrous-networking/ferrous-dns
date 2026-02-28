use async_trait::async_trait;
use ferrous_dns_domain::{Client, DomainError, Group};

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn create(&self, name: String, comment: Option<String>) -> Result<Group, DomainError>;
    async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Group>, DomainError>;
    async fn get_all(&self) -> Result<Vec<Group>, DomainError>;
    async fn get_all_with_client_counts(&self) -> Result<Vec<(Group, u64)>, DomainError>;
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
    ) -> Result<Group, DomainError>;
    async fn delete(&self, id: i64) -> Result<(), DomainError>;
    async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError>;
    async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError>;
}
