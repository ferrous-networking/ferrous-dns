use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;

#[async_trait]
pub trait HostnameResolver: Send + Sync {
    /// Perform reverse DNS lookup (PTR) for an IP address
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError>;
}
