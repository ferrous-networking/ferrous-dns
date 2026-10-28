use async_trait::async_trait;
use ferrous_dns_domain::{Client, ClientStats, DomainError, HostnameSource};
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

    /// Sets the client's name, as given by `source`. A name set by hand is
    /// only ever replaced by hand, and an mDNS name by PTR only once it has
    /// gone a day without being announced again: such a write changes nothing.
    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
        source: HostnameSource,
    ) -> Result<(), DomainError>;

    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError>;

    /// One page of clients, most recently seen first, and how many there are
    /// in all; with `active_days`, only those seen within that many days.
    async fn get_page(
        &self,
        active_days: Option<u32>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Client>, u64), DomainError>;

    async fn get_stats(&self) -> Result<ClientStats, DomainError>;

    async fn count_active_since(&self, hours: f32) -> Result<u64, DomainError>;

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError>;

    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    /// Clients the hostname sync should look up again; never ones named by hand.
    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError>;

    async fn get_by_ip(&self, ip_address: IpAddr) -> Result<Option<Client>, DomainError>;

    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError>;

    /// Replaces the comment of the client `id`; `None` clears it.
    async fn set_comment(&self, id: i64, comment: Option<String>) -> Result<(), DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
