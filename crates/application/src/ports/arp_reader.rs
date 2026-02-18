use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::collections::HashMap;
use std::net::IpAddr;

pub type ArpTable = HashMap<IpAddr, String>;

#[async_trait]
pub trait ArpReader: Send + Sync {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError>;
}
