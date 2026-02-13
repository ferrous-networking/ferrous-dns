use async_trait::async_trait;
use ferrous_dns_domain::{Client, ClientStats, DomainError};
use std::net::IpAddr;

#[async_trait]
pub trait ClientRepository: Send + Sync {
    /// Get or create a client by IP address
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError>;

    /// Update client's last seen timestamp and increment query count
    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError>;

    /// Update client's MAC address
    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError>;

    /// Batch update MAC addresses for multiple clients (more efficient)
    async fn batch_update_mac_addresses(
        &self,
        updates: Vec<(IpAddr, String)>,
    ) -> Result<u64, DomainError>;

    /// Update client's hostname
    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
    ) -> Result<(), DomainError>;

    /// Get all clients (with pagination)
    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError>;

    /// Get active clients (last_seen within N days)
    async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError>;

    /// Get client statistics
    async fn get_stats(&self) -> Result<ClientStats, DomainError>;

    /// Delete clients not seen in N days (data retention)
    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError>;

    /// Get clients that need MAC address updates
    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    /// Get clients that need hostname updates
    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    /// Get a client by ID
    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError>;

    /// Assign a client to a group
    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError>;

    /// Delete a client by ID
    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
