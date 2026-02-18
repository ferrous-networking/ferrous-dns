use async_trait::async_trait;
use ferrous_dns_domain::{ClientSubnet, DomainError};

#[async_trait]
pub trait ClientSubnetRepository: Send + Sync {
    
    async fn create(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError>;

    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn exists(&self, subnet_cidr: &str) -> Result<bool, DomainError>;
}
