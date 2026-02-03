use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::net::IpAddr;

/// Result of a DNS resolution with metadata
#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub addresses: Vec<IpAddr>,
    pub cache_hit: bool,
}

impl DnsResolution {
    pub fn new(addresses: Vec<IpAddr>, cache_hit: bool) -> Self {
        Self {
            addresses,
            cache_hit,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;
}
