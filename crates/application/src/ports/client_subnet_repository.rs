use async_trait::async_trait;
use ferrous_dns_domain::{ClientSubnet, DomainError};

#[async_trait]
pub trait ClientSubnetRepository: Send + Sync {
    /// Create a new subnet configuration
    async fn create(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError>;

    /// Get subnet by ID
    async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError>;

    /// Get all subnets (for caching/matching)
    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError>;

    /// Delete a subnet
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Check if CIDR already exists
    async fn exists(&self, subnet_cidr: &str) -> Result<bool, DomainError>;
}
