use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::net::IpAddr;

#[async_trait]
pub trait DnsResolver: Send + Sync {

    async fn resolve(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DomainError>;
}
