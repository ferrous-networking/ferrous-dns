use async_trait::async_trait;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use ipnetwork::IpNetwork;

#[async_trait]
pub trait ClientSubnetRepository: Send + Sync {
    /// `network` must be canonical (as returned by `ClientSubnet::parse_cidr`).
    async fn create(
        &self,
        network: IpNetwork,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError>;

    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError>;

    /// Replaces the group and comment of the subnet `id`.
    async fn update(
        &self,
        id: i64,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn exists(&self, network: IpNetwork) -> Result<bool, DomainError>;
}
