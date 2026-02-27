use async_trait::async_trait;
use ferrous_dns_domain::{Client, ClientStats, DomainError};
use std::net::IpAddr;

#[async_trait]
pub trait ClientRepository: Send + Sync {
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError>;

    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError>;

    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError>;

    async fn batch_update_mac_addresses(
        &self,
        updates: Vec<(IpAddr, String)>,
    ) -> Result<u64, DomainError>;

    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
    ) -> Result<(), DomainError>;

    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError>;

    async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError>;

    async fn get_stats(&self) -> Result<ClientStats, DomainError>;

    async fn count_active_since(&self, hours: f32) -> Result<u64, DomainError>;

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError>;

    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError>;

    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
