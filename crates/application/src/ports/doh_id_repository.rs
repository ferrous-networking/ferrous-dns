use async_trait::async_trait;
use ferrous_dns_domain::{DohId, DomainError};

#[async_trait]
pub trait DohIdRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        client_id: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<DohId>, DomainError>;

    async fn get_by_client_id(&self, client_id: &str) -> Result<Option<DohId>, DomainError>;

    async fn get_all(&self) -> Result<Vec<DohId>, DomainError>;

    async fn update(
        &self,
        id: i64,
        name: String,
        client_id: Option<String>,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
