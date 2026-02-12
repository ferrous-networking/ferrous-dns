use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::collections::HashMap;
use std::net::IpAddr;

/// Mapping from IP address to MAC address
pub type ArpTable = HashMap<IpAddr, String>;

#[async_trait]
pub trait ArpReader: Send + Sync {
    /// Read the system ARP cache and return IP->MAC mappings
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError>;
}
