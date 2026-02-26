use async_trait::async_trait;
use ferrous_dns_domain::{CustomService, DomainError};

#[async_trait]
pub trait CustomServiceRepository: Send + Sync {
    async fn create(
        &self,
        service_id: &str,
        name: &str,
        category_name: &str,
        domains: &[String],
    ) -> Result<CustomService, DomainError>;

    async fn get_by_service_id(
        &self,
        service_id: &str,
    ) -> Result<Option<CustomService>, DomainError>;

    async fn get_all(&self) -> Result<Vec<CustomService>, DomainError>;

    async fn update(
        &self,
        service_id: &str,
        name: Option<String>,
        category_name: Option<String>,
        domains: Option<Vec<String>>,
    ) -> Result<CustomService, DomainError>;

    async fn delete(&self, service_id: &str) -> Result<(), DomainError>;
}
